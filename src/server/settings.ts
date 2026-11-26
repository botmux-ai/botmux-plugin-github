import { dirname } from 'node:path';
import type {
  PluginConfig,
  PluginConfigPatch,
  RedactedPluginConfig,
} from '../types.ts';
import {
  apiOriginChanged,
  applyConfigPatch,
  createDefaultConfig,
  normalizeAndValidateConfig,
  redactConfig,
  registerConfigSecrets,
} from '../config/schema.ts';
import {
  readControlTokenIfExists,
  resolvePluginHome,
} from '../config/store.ts';
import { readSecureFileIfExists } from '../security/fs.ts';
import { StateStore, StateCorruptError, createEmptyState } from '../state/store.ts';
import { GitHubClient } from '../github/client.ts';
import { GitHubWatcher } from '../engine/watcher.ts';
import { loopbackRequest } from '../security/net.ts';
import { SecretRegistry, formatSafeError } from '../security/redact.ts';
import {
  discoverOnlineDaemons,
  loadBotsConfig,
} from '../host/discovery.ts';

export interface PluginConfigApi {
  path: string;
  get<T = unknown>(key?: string): T | undefined;
  set(key: string, value: unknown): void;
  replace(value: Record<string, unknown>): void;
}

export interface SettingsApi {
  config: PluginConfigApi;
}

type LocalServiceCallOutcome =
  | { kind: 'ok'; port: number; status: number; json: unknown }
  | { kind: 'http_error'; port: number; status: number; json: unknown }
  | { kind: 'timeout'; port: number; error: string }
  | { kind: 'unreachable' };

function getAllowInsecureTestFlag(): boolean {
  return process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
}

/**
 * Strictly loads existing config from Botmux's config API (or disk if present):
 * - Returns default config ONLY when no config exists yet (empty {} and ENOENT on disk).
 * - Throws immediately if an existing config fails JSON parse or schema validation
 *   so saveSettings NEVER wipes stored PATs, keys, or repository rules with defaults!
 */
async function loadExistingConfigStrict(
  api: SettingsApi,
  allowInsecure: boolean,
): Promise<PluginConfig> {
  // Always verify on-disk config.json is not a symlink or non-regular file when path exists
  let onDiskBuf: Buffer | null = null;
  if (api.config.path) {
    onDiskBuf = await readSecureFileIfExists(api.config.path, {
      maxBytes: 1024 * 1024,
      rejectHardlinks: false,
    });
  }

  const rawFromApi = api.config.get();
  if (rawFromApi !== undefined) {
    if (!rawFromApi || typeof rawFromApi !== 'object' || Array.isArray(rawFromApi)) {
      throw new Error('Existing configuration must be a JSON object');
    }
    if (Object.keys(rawFromApi as Record<string, unknown>).length > 0) {
      return normalizeAndValidateConfig(rawFromApi, {
        allowInsecureLocalApiForTests: allowInsecure,
      });
    }
  }

  // If api.config.get() returned empty/undefined, verify whether config.json actually exists on disk!
  if (onDiskBuf !== null) {
    const trimmed = onDiskBuf.toString('utf8').trim();
    if (trimmed.length === 0) {
      throw new Error(`Existing config file at ${api.config.path} is empty/corrupt`);
    }
    const parsed: unknown = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`Existing config file at ${api.config.path} must be a JSON object`);
    }
    return normalizeAndValidateConfig(parsed, {
      allowInsecureLocalApiForTests: allowInsecure,
    });
  }

  return createDefaultConfig();
}

function resolveCandidatePorts(boundPort: number | undefined, configPort: number): number[] {
  const envPort = Number(process.env.BOTMUX_GITHUB_PORT ?? '');
  const raw = [boundPort, configPort, envPort];
  const out: number[] = [];
  for (const p of raw) {
    if (typeof p === 'number' && Number.isInteger(p) && p >= 1 && p <= 65535 && !out.includes(p)) {
      out.push(p);
    }
  }
  return out;
}

/**
 * Calls the local plugin service over 127.0.0.1 node:http across candidate ports
 * (persisted boundPort -> config.service.port -> BOTMUX_GITHUB_PORT).
 * Explicitly distinguishes unreachable (ECONNREFUSED / no token) from timeout/5xx
 * so callers NEVER spawn a duplicate in-process watcher when the live service already accepted work.
 */
async function callLocalService(opts: {
  pluginHome: string;
  ports: number[];
  method: 'GET' | 'POST';
  path: string;
  body?: unknown;
  timeoutMs: number;
}): Promise<LocalServiceCallOutcome> {
  const token = await readControlTokenIfExists(opts.pluginHome);
  if (!token) return { kind: 'unreachable' };

  const bodyStr = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
  for (const port of opts.ports) {
    const headers: Record<string, string> = {
      Host: `127.0.0.1:${port}`,
      'X-Botmux-Github-Token': token,
      ...(opts.method === 'POST'
        ? {
            'Content-Type': 'application/json',
            'X-Botmux-Plugin-Control': '1',
          }
        : {}),
    };

    try {
      const res = await loopbackRequest({
        host: '127.0.0.1',
        port,
        method: opts.method,
        path: opts.path,
        headers,
        body: bodyStr,
        timeoutMs: opts.timeoutMs,
      });
      let json: unknown = null;
      try {
        json = res.body.length > 0 ? JSON.parse(res.body.toString('utf8')) : null;
      } catch {
        json = null;
      }
      if (res.status >= 200 && res.status < 300) {
        return { kind: 'ok', port, status: res.status, json };
      }
      return { kind: 'http_error', port, status: res.status, json };
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException)?.code;
      // For mutating POST calls, ECONNRESET is an unknown outcome — never fall back to a duplicate executor!
      if (
        code === 'ECONNREFUSED' ||
        code === 'EHOSTUNREACH' ||
        (opts.method === 'GET' && code === 'ECONNRESET')
      ) {
        continue;
      }
      return {
        kind: 'timeout',
        port,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
  return { kind: 'unreachable' };
}

/**
 * Named export required by Botmux Dashboard GET /api/plugins/github/settings.
 * Strictly returns browser-safe redacted settings + live runtime health/mappings.
 */
export async function getSettings(api: SettingsApi): Promise<{
  ok: boolean;
  error?: string;
  configCorrupt?: boolean;
  stateCorrupt?: boolean;
  config: RedactedPluginConfig;
  service: {
    online: boolean;
    mode: string;
    port: number;
    configuredPort: number;
    portRestartRequired: boolean;
    uptimeSec?: number;
    queue?: { active: number; queued: number; pending: number };
  };
  rateLimits: unknown;
  repos: unknown;
  prGroups: unknown;
  recentEvents: unknown;
  botStatus: Array<{
    id: string;
    name: string;
    brand: string;
    online: boolean;
    apiOnly: boolean;
  }>;
}> {
  const allowInsecure = getAllowInsecureTestFlag();
  const pluginHome = api?.config?.path
    ? dirname(api.config.path)
    : resolvePluginHome();
  const registry = new SecretRegistry();

  let config: PluginConfig;
  let configError: string | undefined;
  try {
    config = await loadExistingConfigStrict(api, allowInsecure);
  } catch (err) {
    configError = formatSafeError(err, registry);
    config = createDefaultConfig();
  }
  registerConfigSecrets(config, registry);

  const stateStore = new StateStore(pluginHome, registry);
  let stateError: string | undefined;
  const [state, recentEvents, bots, onlineDaemons] = await Promise.all([
    stateStore.load().catch(err => {
      stateError = formatSafeError(err, registry);
      return createEmptyState();
    }),
    stateStore.readRecentEvents(40).catch(() => []),
    loadBotsConfig(undefined, registry).catch(() => []),
    discoverOnlineDaemons().catch(() => new Map()),
  ]);

  const live = await callLocalService({
    pluginHome,
    ports: resolveCandidatePorts(state.service.boundPort, config.service.port),
    method: 'GET',
    path: '/api/status',
    timeoutMs: 1_200,
  });

  const liveJson =
    live.kind === 'ok' && live.json && typeof live.json === 'object'
      ? (live.json as Record<string, unknown>)
      : null;

  const botStatus = bots.map(b => ({
    id: b.larkAppId,
    name: b.displayName || b.name || b.larkAppId,
    brand: b.brand,
    online: onlineDaemons.has(b.larkAppId),
    apiOnly: b.apiOnly === true,
  }));

  const effectiveBoundPort =
    typeof liveJson?.port === 'number'
      ? liveJson.port
      : live.kind === 'ok'
        ? live.port
        : config.service.port;

  const combinedErr = [configError, stateError].filter(Boolean).join('; ');

  return {
    ok: !configError && !stateError,
    ...(combinedErr ? { error: combinedErr } : {}),
    ...(configError ? { configCorrupt: true } : {}),
    ...(stateError ? { stateCorrupt: true } : {}),
    config: redactConfig(config),
    service: {
      online: Boolean(liveJson),
      mode:
        typeof liveJson?.mode === 'string'
          ? liveJson.mode
          : config.repos.some(r => r.enabled)
            ? state.service.mode
            : 'dormant',
      port: effectiveBoundPort,
      configuredPort: config.service.port,
      portRestartRequired: Boolean(
        liveJson?.portRestartRequired ?? (Boolean(liveJson) && effectiveBoundPort !== config.service.port),
      ),
      ...(typeof liveJson?.uptimeSec === 'number' ? { uptimeSec: liveJson.uptimeSec } : {}),
      ...(liveJson?.queue && typeof liveJson.queue === 'object'
        ? { queue: liveJson.queue as { active: number; queued: number; pending: number } }
        : {}),
    },
    rateLimits: liveJson?.rateLimits ?? state.rateLimits,
    repos: liveJson?.repos ?? state.repos,
    prGroups: liveJson?.prGroups ?? state.prGroups,
    recentEvents: liveJson?.recentEvents ?? recentEvents,
    botStatus,
  };
}

/**
 * Named export required by Botmux Dashboard PUT /api/plugins/github/settings.
 * Executes inside Botmux's 30s withPluginServiceLock:
 * - Strictly fails closed if existing config.json is invalid/corrupt (NEVER wipes PAT or rules with defaults!)
 * - Strictly fast, bounded timeouts, NEVER calls plugin lifecycle start/stop/restart
 * - Never throws unhandled errors (always returns structured `{ ok: false, error }`)
 */
export async function saveSettings(
  api: SettingsApi,
  value: unknown,
): Promise<Record<string, unknown>> {
  const allowInsecure = getAllowInsecureTestFlag();
  const pluginHome = api?.config?.path
    ? dirname(api.config.path)
    : resolvePluginHome();
  const registry = new SecretRegistry();

  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ok: false, error: 'Invalid settings payload: expected JSON object' };
    }

    const payload = value as Record<string, unknown>;
    const action = typeof payload.action === 'string' ? payload.action : 'saveConfig';

    // CRITICAL: Fail closed if existing config is corrupt/invalid — NEVER substitute empty defaults!
    const current = await loadExistingConfigStrict(api, allowInsecure);
    registerConfigSecrets(current, registry);

    const stateStore = new StateStore(pluginHome, registry);
    let boundPort: number | undefined;
    try {
      const state = await stateStore.load();
      boundPort = state.service.boundPort;
    } catch (err) {
      if (!(err instanceof StateCorruptError)) throw err;
      // Allow saving config even if state.json needs manual repair, while non-config actions fail closed
      if (action !== 'saveConfig') {
        return { ok: false, error: formatSafeError(err, registry) };
      }
    }
    const candidatePorts = resolveCandidatePorts(boundPort, current.service.port);

    if (action === 'testAuth') {
      const repo = typeof payload.repo === 'string' ? payload.repo.trim() : undefined;
      let incomingPatch: PluginConfigPatch | undefined;
      if (Object.hasOwn(payload, 'patch') && payload.patch !== undefined) {
        if (!payload.patch || typeof payload.patch !== 'object' || Array.isArray(payload.patch)) {
          return { ok: false, error: 'Invalid settings patch: expected JSON object' };
        }
        incomingPatch = payload.patch as PluginConfigPatch;
      }

      // Refuse attaching stored write-only credentials to an unsaved patch pointing at a different origin
      if (incomingPatch && apiOriginChanged(current.github.apiBaseUrl, incomingPatch.github?.apiBaseUrl)) {
        const suppliedPat = Boolean(incomingPatch.github?.pat);
        const suppliedKey = Boolean(incomingPatch.github?.app?.privateKeyPem);
        if (!suppliedPat && !suppliedKey && incomingPatch.github?.mode !== 'gh_cli') {
          return {
            ok: false,
            error:
              'Changing github.apiBaseUrl origin requires explicitly supplying credentials for the new origin.',
          };
        }
      }

      const effectiveConfig = incomingPatch
        ? applyConfigPatch(current, incomingPatch, {
            allowInsecureLocalApiForTests: allowInsecure,
          })
        : current;
      registerConfigSecrets(effectiveConfig, registry);

      if (!incomingPatch) {
        const viaService = await callLocalService({
          pluginHome,
          ports: candidatePorts,
          method: 'POST',
          path: '/api/test-auth',
          body: { ...(repo ? { repo } : {}) },
          timeoutMs: 5_000,
        });
        if (viaService.kind === 'ok' && viaService.json && typeof viaService.json === 'object') {
          return viaService.json as Record<string, unknown>;
        }
        if (viaService.kind === 'timeout') {
          return { ok: false, error: `Auth test timed out contacting plugin service: ${viaService.error}` };
        }
      }

      const client = new GitHubClient({
        auth: effectiveConfig.github,
        proxy: effectiveConfig.proxy,
        registry,
        allowInsecureLocalForTests: allowInsecure,
      });
      const result = await client.testAuth({ repo, timeoutMs: 5_000 });
      return result as unknown as Record<string, unknown>;
    }

    if (action === 'sync') {
      const repo =
        typeof payload.repo === 'string' && payload.repo.trim() ? payload.repo.trim() : undefined;
      const dryRun = payload.dryRun === true;
      const viaService = await callLocalService({
        pluginHome,
        ports: candidatePorts,
        method: 'POST',
        path: '/api/sync',
        body: { ...(repo ? { repo } : {}), dryRun, async: !dryRun },
        timeoutMs: dryRun ? 5_000 : 2_500,
      });
      if (
        (viaService.kind === 'ok' || viaService.kind === 'http_error') &&
        viaService.json &&
        typeof viaService.json === 'object'
      ) {
        return viaService.json as Record<string, unknown>;
      }
      if (viaService.kind === 'timeout') {
        return {
          ok: false,
          error: 'Background plugin service timed out responding to sync; check service status rather than re-running.',
        };
      }
      if (dryRun) {
        const watcher = new GitHubWatcher({
          config: current,
          stateStore,
          registry,
          allowInsecureLocalApiForTests: allowInsecure,
        });
        const res = await watcher.sync({ repo, dryRun: true });
        return res as unknown as Record<string, unknown>;
      }
      return {
        ok: false,
        error:
          'Background plugin service is not running; start the GitHub service or run `botmux github:sync`.',
      };
    }

    if (action === 'openPr') {
      const repo = typeof payload.repo === 'string' ? payload.repo.trim() : '';
      const prNumber = Number(payload.prNumber ?? 0);
      const dryRun = payload.dryRun === true;

      // Always send async: true for live openPr so Botmux's 30s withPluginServiceLock releases immediately!
      const viaService = await callLocalService({
        pluginHome,
        ports: candidatePorts,
        method: 'POST',
        path: '/api/open-pr',
        body: { repo, prNumber, dryRun, async: !dryRun },
        timeoutMs: dryRun ? 5_000 : 2_500,
      });
      if (
        (viaService.kind === 'ok' || viaService.kind === 'http_error') &&
        viaService.json &&
        typeof viaService.json === 'object'
      ) {
        return viaService.json as Record<string, unknown>;
      }
      if (viaService.kind === 'timeout') {
        return {
          ok: false,
          error:
            'Background plugin service timed out responding to open-pr; check PR mappings before retrying.',
        };
      }
      if (dryRun) {
        const watcher = new GitHubWatcher({
          config: current,
          stateStore,
          registry,
          allowInsecureLocalApiForTests: allowInsecure,
        });
        const res = await watcher.openPr({ repo, prNumber, dryRun: true });
        return res as unknown as Record<string, unknown>;
      }
      // Never block Botmux's global 30s withPluginServiceLock with a live group-creation flow when service is offline
      return {
        ok: false,
        error:
          'Background plugin service is not running; start the GitHub service or run `botmux github:open-pr <owner/repo#N>`.',
      };
    }

    // Default: saveConfig
    let patch: PluginConfigPatch;
    if (Object.hasOwn(payload, 'patch') && payload.patch !== undefined) {
      if (!payload.patch || typeof payload.patch !== 'object' || Array.isArray(payload.patch)) {
        return { ok: false, error: 'Invalid settings patch: expected JSON object' };
      }
      patch = payload.patch as PluginConfigPatch;
    } else {
      patch = payload as PluginConfigPatch;
    }

    const next = applyConfigPatch(current, patch, {
      allowInsecureLocalApiForTests: allowInsecure,
    });
    registerConfigSecrets(next, registry);
    api.config.replace(next as unknown as Record<string, unknown>);

    const reloadResp = await callLocalService({
      pluginHome,
      ports: candidatePorts,
      method: 'POST',
      path: '/api/reload',
      body: {},
      timeoutMs: 1_500,
    });

    const effectiveBoundPort = reloadResp.kind === 'ok' ? reloadResp.port : boundPort;
    return {
      ok: true,
      reloaded: reloadResp.kind === 'ok',
      portRestartRequired: Boolean(effectiveBoundPort && effectiveBoundPort !== next.service.port),
      config: redactConfig(next),
    };
  } catch (err) {
    return {
      ok: false,
      error: formatSafeError(err, registry),
    };
  }
}
