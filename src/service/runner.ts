import http from 'node:http';
import { createHash } from 'node:crypto';
import { watch as fsWatch, realpathSync, type FSWatcher } from 'node:fs';
import { resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PluginConfig } from '../types.ts';
import {
  DEFAULT_SERVICE_PORT,
  DEFAULT_WEBHOOK_PATH,
  MAX_WEBHOOK_BODY_BYTES,
  PLUGIN_ID,
} from '../types.ts';
import {
  ensureControlToken,
  getConfigPath,
  loadPluginConfig,
  resolvePluginHome,
} from '../config/store.ts';
import { redactConfig, validateRepoSlug } from '../config/schema.ts';
import { StateStore } from '../state/store.ts';
import { GitHubWatcher } from '../engine/watcher.ts';
import type { GhCliRunner } from '../github/auth.ts';
import type { DiscoveryOptions } from '../host/discovery.ts';
import { loadDashboardSecret } from '../host/discovery.ts';
import type { LarkOpenApiClient } from '../host/lark.ts';
import type { CliExecFn } from '../host/bridge.ts';
import {
  MAX_CONTROL_BODY_BYTES,
  RequestBodyError,
  authorizeControlRequest,
  isAllowedLoopbackHost,
  isLoopbackRemoteAddress,
  readRawBodyBounded,
  verifyAndParseWebhookPayload,
  verifyWebhookHostToken,
} from '../engine/webhook.ts';
import { readSecureFileIfExists } from '../security/fs.ts';
import { SecretRegistry, defaultSecretRegistry, formatSafeError } from '../security/redact.ts';

export interface ReloadOutcome {
  ok: boolean;
  mode?: string;
  enabledRuleCount?: number;
  portRestartRequired?: boolean;
  error?: string;
}

export interface RunningServiceHandle {
  port: number;
  controlToken: string;
  registry: SecretRegistry;
  watcher: GitHubWatcher;
  server: http.Server;
  reload(): Promise<ReloadOutcome>;
  close(): Promise<void>;
}

export interface StartServiceOptions {
  pluginHome?: string;
  port?: number;
  registry?: SecretRegistry;
  discovery?: DiscoveryOptions;
  ghRunner?: GhCliRunner;
  larkClient?: LarkOpenApiClient;
  cliExec?: CliExecFn;
  webhookHostToken?: string;
  maxPendingPerKey?: number;
  maxGlobalPending?: number;
  maxInFlightDeliveries?: number;
  allowInsecureLocalApiForTests?: boolean;
  configPollIntervalMs?: number;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  if (res.writableEnded || res.destroyed) return;
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

async function computeFileHash(filePath: string): Promise<string> {
  try {
    const buf = await readSecureFileIfExists(filePath, {
      maxBytes: 1024 * 1024,
      rejectHardlinks: false,
    });
    if (!buf) return 'missing';
    return createHash('sha256').update(buf).digest('hex');
  } catch {
    return 'unreadable';
  }
}

export async function startGitHubService(
  opts: StartServiceOptions = {},
): Promise<RunningServiceHandle> {
  const pluginHome = resolvePluginHome({ pluginHome: opts.pluginHome });
  const registry = opts.registry ?? new SecretRegistry();
  const stateStore = new StateStore(pluginHome, registry);
  const controlToken = await ensureControlToken(pluginHome);
  registry.register(controlToken);

  const allowInsecure =
    opts.allowInsecureLocalApiForTests === true ||
    process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';

  let config: PluginConfig = await loadPluginConfig(pluginHome, {
    allowInsecureLocalApiForTests: allowInsecure,
  });

  const envPort = Number(process.env.PORT ?? process.env.BOTMUX_GITHUB_PORT ?? '');
  const desiredPort =
    opts.port !== undefined
      ? opts.port
      : Number.isInteger(envPort) && envPort >= 0 && envPort <= 65535
        ? envPort
        : config.service.port || DEFAULT_SERVICE_PORT;

  const watcher = new GitHubWatcher({
    config,
    stateStore,
    discovery: opts.discovery,
    registry,
    ghRunner: opts.ghRunner,
    larkClient: opts.larkClient,
    cliExec: opts.cliExec,
    maxPendingPerKey: opts.maxPendingPerKey,
    maxGlobalPending: opts.maxGlobalPending,
    maxInFlightDeliveries: opts.maxInFlightDeliveries,
    allowInsecureLocalApiForTests: allowInsecure,
  });

  await watcher.start();

  const seenNonces = new Map<string, number>();
  const startedAtMs = Date.now();
  let inFlightRequests = 0;
  const maxInFlightRequests = 16;
  let boundPort = desiredPort;

  // Strictly isolate webhook host token (BOTMUX_PLUGIN_WEBHOOK_TOKEN from deepcoldy/botmux#3830)
  // from control API bearer tokens so a webhook caller can NEVER access /api/* control routes!
  const webhookHostToken =
    (opts.webhookHostToken ?? process.env.BOTMUX_PLUGIN_WEBHOOK_TOKEN)?.trim() || undefined;
  if (webhookHostToken) registry.register(webhookHostToken);

  const hostBearerTokens = [
    process.env.BOTMUX_PLUGIN_SERVICE_TOKEN,
    process.env.BOTMUX_PLUGIN_CARD_ACTION_TOKEN,
    process.env.BOTMUX_SERVICE_AUTH,
  ].filter((t): t is string => Boolean(t && t.trim()));
  for (const t of hostBearerTokens) registry.register(t);

  const configPath = getConfigPath(pluginHome);
  let lastConfigHash = await computeFileHash(configPath);
  let reloadPromise: Promise<ReloadOutcome> | null = null;

  const reload = async (): Promise<ReloadOutcome> => {
    if (reloadPromise) return reloadPromise;
    reloadPromise = (async (): Promise<ReloadOutcome> => {
      try {
        const nextHash = await computeFileHash(configPath);
        const nextConfig = await loadPluginConfig(pluginHome, {
          allowInsecureLocalApiForTests: allowInsecure,
        });
        // Commit config and lastConfigHash ONLY AFTER watcher.reloadConfig succeeds!
        await watcher.reloadConfig(nextConfig);
        config = nextConfig;
        lastConfigHash = nextHash;
        return {
          ok: true,
          mode: watcher.getMode(),
          enabledRuleCount: watcher.getEnabledRules().length,
          portRestartRequired: config.service.port !== boundPort,
        };
      } catch (err) {
        const safeErr = formatSafeError(err, registry);
        await stateStore
          .appendEvent({
            level: 'error',
            kind: 'config_reload_error',
            message: `Failed to reload config.json: ${safeErr}`,
          })
          .catch(() => {});
        return {
          ok: false,
          error: safeErr,
        };
      } finally {
        reloadPromise = null;
      }
    })();
    return reloadPromise;
  };

  const server = http.createServer(async (req, res) => {
    if (inFlightRequests >= maxInFlightRequests) {
      sendJson(res, 503, { ok: false, error: 'server_busy' });
      return;
    }
    inFlightRequests++;
    try {
      await handleRequest(req, res);
    } catch (err) {
      if (err instanceof RequestBodyError) {
        sendJson(res, err.status, { ok: false, error: err.message });
      } else {
        sendJson(res, 500, { ok: false, error: 'internal_error' });
      }
    } finally {
      inFlightRequests--;
    }
  });

  // Hardened HTTP server timeouts & connection limits
  server.headersTimeout = 10_000;
  server.requestTimeout = 20_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.maxConnections = 64;

  const isWebhookRoute = (pathname: string): boolean => {
    const configured = config.webhook.path || DEFAULT_WEBHOOK_PATH;
    return (
      pathname === configured ||
      pathname === '/webhooks/github' ||
      pathname === '/webhook/plugin/github' ||
      pathname === '/webhook/plugin/github/events'
    );
  };

  const handleRequest = async (
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> => {
    const method = (req.method ?? 'GET').toUpperCase();
    let pathname: string;
    try {
      pathname = new URL(req.url ?? '/', `http://127.0.0.1:${boundPort}`).pathname;
    } catch {
      sendJson(res, 400, { ok: false, error: 'invalid_url' });
      return;
    }

    // 1. Unauthenticated minimal health route (still enforces loopback + Host + no Origin)
    if (method === 'GET' && (pathname === '/' || pathname === '/health')) {
      if (!isLoopbackRemoteAddress(req.socket?.remoteAddress)) {
        sendJson(res, 403, { ok: false, error: 'forbidden' });
        return;
      }
      if (req.headers.origin) {
        sendJson(res, 403, { ok: false, error: 'forbidden' });
        return;
      }
      if (!isAllowedLoopbackHost(req.headers.host, boundPort)) {
        sendJson(res, 403, { ok: false, error: 'invalid_host' });
        return;
      }
      sendJson(res, 200, {
        ok: true,
        pluginId: PLUGIN_ID,
        mode: watcher.getMode(),
        port: boundPort,
        configuredPort: config.service.port,
        portRestartRequired: config.service.port !== boundPort,
        enabledRuleCount: watcher.getEnabledRules().length,
        uptimeSec: Math.floor((Date.now() - startedAtMs) / 1000),
      });
      return;
    }

    // 2. GitHub Webhook receiver (loopback, authenticated by BOTMUX_PLUGIN_WEBHOOK_TOKEN when injected + raw-byte HMAC-SHA256)
    if (isWebhookRoute(pathname)) {
      if (method !== 'POST') {
        sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
        return;
      }
      if (!isLoopbackRemoteAddress(req.socket?.remoteAddress)) {
        sendJson(res, 403, { ok: false, error: 'remote_not_loopback' });
        return;
      }
      // Enforce BOTMUX_PLUGIN_WEBHOOK_TOKEN Bearer check when running behind Botmux #3830 webhook gateway
      if (webhookHostToken && !verifyWebhookHostToken(req.headers, webhookHostToken)) {
        sendJson(res, 401, { ok: false, error: 'invalid_webhook_host_token' });
        return;
      }
      // Fail closed BEFORE reading body if webhook is disabled or secret invalid
      if (!config.webhook.enabled || !config.webhook.secret) {
        sendJson(res, 503, { ok: false, error: 'webhook_not_configured' });
        return;
      }

      const rawBody = await readRawBodyBounded(req, {
        maxBytes: MAX_WEBHOOK_BODY_BYTES,
        timeoutMs: 10_000,
      });

      const verdict = verifyAndParseWebhookPayload({
        headers: req.headers,
        rawBody,
        webhookEnabled: config.webhook.enabled,
        webhookSecret: config.webhook.secret,
        allowedRepoKeys: watcher.getAllowedRepoKeys(),
        dedupCache: watcher.deliveryDedup,
      });

      if (!verdict.ok) {
        if (verdict.status === 503) {
          res.setHeader('Retry-After', '5');
        }
        sendJson(res, verdict.status, { ok: false, error: verdict.reason ?? 'rejected' });
        return;
      }

      if (verdict.status === 204) {
        res.writeHead(204);
        res.end();
        return;
      }

      if (verdict.parsed?.event === 'ping') {
        sendJson(res, 200, { ok: true, event: 'ping' });
        return;
      }

      if (verdict.duplicate) {
        sendJson(res, 200, { ok: true, duplicate: true });
        return;
      }

      if (verdict.parsed?.event === 'pull_request' && verdict.parsed.pr && verdict.parsed.action) {
        const admission = watcher.enqueueWebhookPrEvent({
          deliveryId: verdict.parsed.deliveryId,
          action: verdict.parsed.action,
          pr: verdict.parsed.pr,
        });
        if (!admission.accepted) {
          res.setHeader('Retry-After', '5');
          sendJson(res, admission.status, {
            ok: false,
            error: admission.reason,
          });
          return;
        }
        sendJson(res, 202, {
          ok: true,
          accepted: true,
          deliveryId: verdict.parsed.deliveryId,
        });
        return;
      }

      sendJson(res, 200, { ok: true });
      return;
    }

    // 3. Authenticated local control API routes (/api/*)
    if (pathname.startsWith('/api/')) {
      const dashboardSecret = await loadDashboardSecret(opts.discovery, registry);
      const auth = authorizeControlRequest({
        req,
        boundPort,
        controlToken,
        dashboardSecret,
        hostBearerTokens,
        seenNonces,
      });
      if (!auth.ok) {
        sendJson(res, auth.status, { ok: false, error: auth.reason });
        return;
      }

      if (method === 'GET' && pathname === '/api/status') {
        const state = await stateStore.load();
        const recentEvents = await stateStore.readRecentEvents(40);
        sendJson(res, 200, {
          ok: true,
          pluginId: PLUGIN_ID,
          mode: watcher.getMode(),
          port: boundPort,
          configuredPort: config.service.port,
          portRestartRequired: config.service.port !== boundPort,
          uptimeSec: Math.floor((Date.now() - startedAtMs) / 1000),
          queue: watcher.getQueueStats(),
          config: redactConfig(config),
          rateLimits: state.rateLimits,
          repos: state.repos,
          prGroups: state.prGroups,
          recentEvents,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/reload') {
        await readRawBodyBounded(req, { maxBytes: MAX_CONTROL_BODY_BYTES, timeoutMs: 5_000 });
        const reloadRes = await reload();
        sendJson(res, reloadRes.ok ? 200 : 500, reloadRes);
        return;
      }

      if (method === 'POST' && pathname === '/api/test-auth') {
        const raw = await readRawBodyBounded(req, {
          maxBytes: MAX_CONTROL_BODY_BYTES,
          timeoutMs: 5_000,
        });
        const body = raw.length > 0 ? (JSON.parse(raw.toString('utf8')) as { repo?: string }) : {};
        const result = await watcher.testAuth({ repo: body.repo, timeoutMs: 8_000 });
        sendJson(res, 200, result);
        return;
      }

      if (method === 'POST' && pathname === '/api/sync') {
        const raw = await readRawBodyBounded(req, {
          maxBytes: MAX_CONTROL_BODY_BYTES,
          timeoutMs: 5_000,
        });
        const body =
          raw.length > 0
            ? (JSON.parse(raw.toString('utf8')) as {
                repo?: string;
                dryRun?: boolean;
                async?: boolean;
              })
            : {};
        if (body.async === true) {
          void watcher.sync({ repo: body.repo, dryRun: body.dryRun === true });
          sendJson(res, 202, { ok: true, accepted: true });
          return;
        }
        const result = await watcher.sync({ repo: body.repo, dryRun: body.dryRun === true });
        sendJson(res, 200, result);
        return;
      }

      if (method === 'POST' && pathname === '/api/open-pr') {
        const raw = await readRawBodyBounded(req, {
          maxBytes: MAX_CONTROL_BODY_BYTES,
          timeoutMs: 5_000,
        });
        const body =
          raw.length > 0
            ? (JSON.parse(raw.toString('utf8')) as {
                repo?: string;
                prNumber?: number;
                dryRun?: boolean;
                async?: boolean;
              })
            : {};
        if (body.async === true && body.dryRun !== true) {
          const rawRepo = String(body.repo ?? '').trim();
          const prNumber = Number(body.prNumber ?? 0);
          let repo: string;
          try {
            repo = validateRepoSlug(rawRepo);
          } catch {
            sendJson(res, 400, { ok: false, error: 'Invalid repo slug' });
            return;
          }
          if (!Number.isSafeInteger(prNumber) || prNumber < 1) {
            sendJson(res, 400, { ok: false, error: 'Invalid prNumber' });
            return;
          }
          void watcher.openPr({ repo, prNumber, dryRun: false });
          sendJson(res, 202, { ok: true, accepted: true, repo, prNumber });
          return;
        }
        const result = await watcher.openPr({
          repo: String(body.repo ?? ''),
          prNumber: Number(body.prNumber ?? 0),
          dryRun: body.dryRun === true,
        });
        sendJson(res, result.ok ? 200 : 400, result);
        return;
      }

      sendJson(res, 404, { ok: false, error: 'not_found' });
      return;
    }

    sendJson(res, 404, { ok: false, error: 'not_found' });
  };

  // Strictly bind ONLY to 127.0.0.1!
  await new Promise<void>((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen(desiredPort, '127.0.0.1', () => {
      server.off('error', rejectPromise);
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        boundPort = addr.port;
      }
      resolvePromise();
    });
  });

  // Persist live boundPort and pid into state.json so settings/CLI always reach the live process
  // even after config.service.port is changed prior to restart.
  await stateStore.update(s => {
    s.service.boundPort = boundPort;
    s.service.pid = process.pid;
    s.service.lastHeartbeatAt = new Date().toISOString();
  });

  // Watch pluginHome directory (NOT config.json inode, which breaks on atomic rename) + fallback hash poll
  let dirWatcher: FSWatcher | null = null;
  try {
    dirWatcher = fsWatch(pluginHome, (_eventType, filename) => {
      if (!filename || filename === 'config.json') {
        void checkConfigReload();
      }
    });
    dirWatcher.unref?.();
  } catch {
    // Fallback timer still handles live reload
  }

  const checkConfigReload = async () => {
    try {
      const nextHash = await computeFileHash(configPath);
      if (nextHash !== lastConfigHash) {
        await reload();
      }
    } catch {
      // Never crash daemon with unhandledRejection on background config hash poll
    }
  };

  const pollConfigInterval = setInterval(() => {
    void checkConfigReload();
  }, opts.configPollIntervalMs ?? 5_000);
  pollConfigInterval.unref?.();

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clearInterval(pollConfigInterval);
    if (dirWatcher) {
      try {
        dirWatcher.close();
      } catch {
        // Ignore
      }
      dirWatcher = null;
    }
    await watcher.stop(7_000);
    await new Promise<void>(resolvePromise => {
      server.close(() => resolvePromise());
      if (typeof server.closeIdleConnections === 'function') {
        server.closeIdleConnections();
      }
    });
    await stateStore
      .update(s => {
        if (s.service.pid === process.pid) {
          delete s.service.boundPort;
          delete s.service.pid;
        }
      })
      .catch(() => {});
  };

  return {
    port: boundPort,
    controlToken,
    registry,
    watcher,
    server,
    reload,
    close,
  };
}

// Run as standalone daemon when executed directly by Botmux FleetSupervisor or node/bun
function isExecutedDirectly(): boolean {
  if (typeof process.argv[1] !== 'string' || !process.argv[1]) return false;
  try {
    const selfPath = realpathSync(fileURLToPath(import.meta.url));
    const entryPath = realpathSync(resolvePath(process.argv[1]));
    return selfPath === entryPath;
  } catch {
    return resolvePath(fileURLToPath(import.meta.url)) === resolvePath(process.argv[1]);
  }
}

if (isExecutedDirectly()) {
  let handle: RunningServiceHandle | null = null;
  let shuttingDown = false;
  const sharedRegistry = defaultSecretRegistry;

  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      if (handle) await handle.close();
    } catch (err) {
      process.stderr.write(
        `[plugin-github] Error during ${signal} shutdown: ${formatSafeError(err, handle?.registry ?? sharedRegistry)}\n`,
      );
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  startGitHubService({ registry: sharedRegistry })
    .then(h => {
      handle = h;
      process.stdout.write(
        `[plugin-github] listening on http://127.0.0.1:${h.port} (mode=${h.watcher.getMode()})\n`,
      );
    })
    .catch(err => {
      process.stderr.write(
        `[plugin-github] fatal startup error: ${formatSafeError(err, sharedRegistry)}\n`,
      );
      process.exit(1);
    });
}
