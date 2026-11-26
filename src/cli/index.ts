import { dirname } from 'node:path';
import type { AuthTestResult, OpenPrResult, PluginConfig, SyncResult } from '../types.ts';
import { loadPluginConfig, readControlTokenIfExists, resolvePluginHome } from '../config/store.ts';
import { redactConfig, registerConfigSecrets, validateRepoSlug } from '../config/schema.ts';
import { StateStore } from '../state/store.ts';
import { GitHubWatcher } from '../engine/watcher.ts';
import { loopbackRequest } from '../security/net.ts';
import { SecretRegistry, formatSafeError } from '../security/redact.ts';

export interface CliConfigApi {
  path?: string;
  get?<T = unknown>(key?: string): T | undefined;
}

export interface CliApi {
  runtime?: string;
  logger?: Console;
  config?: CliConfigApi;
}

export interface CliContext {
  args?: string[];
  api?: CliApi;
}

type ServiceRpcOutcome =
  | { kind: 'ok'; status: number; port: number; json: unknown }
  | { kind: 'http_error'; status: number; port: number; json: unknown }
  | { kind: 'timeout'; port: number; error: string }
  | { kind: 'unreachable' };

function parseBooleanFlag(
  flags: Record<string, string | boolean>,
  name: string,
): boolean {
  const raw = flags[name];
  if (raw === undefined) return false;
  if (raw === true) return true;
  if (raw === false) return false;
  const norm = raw.trim().toLowerCase();
  if (norm === 'true' || norm === '1') return true;
  if (norm === 'false' || norm === '0') return false;
  throw new Error(`Invalid boolean value for --${name}: "${raw}" (expected true or false)`);
}

function parseFlags(args: string[]): { flags: Record<string, string | boolean>; positional: string[] } {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i]!;
    if (token === '--') {
      positional.push(...args.slice(i + 1));
      break;
    }
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq >= 0) {
        flags[token.slice(2, eq)] = token.slice(eq + 1);
      } else {
        const name = token.slice(2);
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('--') && name !== 'dry-run' && name !== 'json') {
          flags[name] = next;
          i++;
        } else {
          flags[name] = true;
        }
      }
    } else {
      positional.push(token);
    }
  }
  return { flags, positional };
}

function assertAllowedArgs(
  flags: Record<string, string | boolean>,
  positional: string[],
  opts: { allowedFlags: readonly string[]; maxPositional: number },
): void {
  const allowed = new Set(opts.allowedFlags);
  for (const key of Object.keys(flags)) {
    if (!allowed.has(key)) {
      throw new Error(`Unknown option: --${key}`);
    }
  }
  if (positional.length > opts.maxPositional) {
    throw new Error(`Unexpected argument: "${positional[opts.maxPositional]}"`);
  }
  for (const pos of positional) {
    if (pos.startsWith('-')) {
      throw new Error(`Unknown option: "${pos}"`);
    }
  }
}

export function parsePrSpec(spec: string): { repo: string; prNumber: number } | null {
  const trimmed = spec.trim();
  const hashIdx = trimmed.lastIndexOf('#');
  if (hashIdx <= 0) return null;
  const repoRaw = trimmed.slice(0, hashIdx).trim();
  const numStr = trimmed.slice(hashIdx + 1).trim();
  if (!/^\d+$/.test(numStr)) return null;
  const prNumber = Number(numStr);
  if (!Number.isSafeInteger(prNumber) || prNumber < 1) return null;
  try {
    const repo = validateRepoSlug(repoRaw);
    return { repo, prNumber };
  } catch {
    return null;
  }
}

async function resolveCliHome(ctx?: CliContext, api?: CliApi): Promise<string> {
  const cfgPath = api?.config?.path ?? ctx?.api?.config?.path;
  if (cfgPath) return dirname(cfgPath);
  return resolvePluginHome();
}

function candidatePorts(boundPort: number | undefined, configPort: number): number[] {
  const envPort = Number(process.env.BOTMUX_GITHUB_PORT ?? '');
  const out: number[] = [];
  for (const p of [boundPort, configPort, envPort]) {
    if (typeof p === 'number' && Number.isInteger(p) && p >= 1 && p <= 65535 && !out.includes(p)) {
      out.push(p);
    }
  }
  return out;
}

async function callRunningService(opts: {
  pluginHome: string;
  ports: number[];
  method: 'GET' | 'POST';
  path: string;
  body?: unknown;
  timeoutMs: number;
}): Promise<ServiceRpcOutcome> {
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
      const json = res.body.length > 0 ? JSON.parse(res.body.toString('utf8')) : null;
      if (res.status >= 200 && res.status < 300) {
        return { kind: 'ok', status: res.status, port, json };
      }
      return { kind: 'http_error', status: res.status, port, json };
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException)?.code;
      // CRITICAL: For mutating POST calls, ONLY ECONNREFUSED/EHOSTUNREACH means the
      // service was unreachable; ECONNRESET after connecting means unknown outcome and
      // MUST NOT fall back to spawning a second in-process watcher!
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

async function createInProcessWatcher(
  pluginHome: string,
  config: PluginConfig,
  registry: SecretRegistry,
): Promise<GitHubWatcher> {
  const allowInsecure = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
  const stateStore = new StateStore(pluginHome, registry);
  return new GitHubWatcher({
    config,
    stateStore,
    registry,
    allowInsecureLocalApiForTests: allowInsecure,
  });
}

function formatStatusText(data: {
  online: boolean;
  mode: string;
  port: number;
  config: ReturnType<typeof redactConfig>;
  rateLimits: Record<string, unknown>;
  repos: Record<string, unknown>;
  prGroups: Record<string, unknown>;
}): string {
  const lines: string[] = [];
  lines.push('@botmux-ai/plugin-github status');
  lines.push(`  Service: ${data.online ? 'online' : 'offline'} (mode=${data.mode}, port=${data.port})`);
  lines.push(
    `  Auth: mode=${data.config.github.mode}, apiBaseUrl=${data.config.github.apiBaseUrl}, hasPat=${data.config.github.hasPat}, hasAppKey=${data.config.github.app.hasPrivateKey}`,
  );
  lines.push(
    `  Webhook: enabled=${data.config.webhook.enabled}, hasSecret=${data.config.webhook.hasSecret}, path=${data.config.webhook.path}`,
  );

  const rl = data.rateLimits as {
    core?: { remaining: number; limit: number; resetAt: string; low: boolean };
    search?: { remaining: number; limit: number; resetAt: string; low: boolean };
    pausedUntil?: string;
  };
  if (rl.core) {
    lines.push(
      `  RateLimit (core): ${rl.core.remaining}/${rl.core.limit} (low=${rl.core.low}, reset=${rl.core.resetAt})`,
    );
  }
  if (rl.search) {
    lines.push(
      `  RateLimit (search): ${rl.search.remaining}/${rl.search.limit} (low=${rl.search.low}, reset=${rl.search.resetAt})`,
    );
  }
  if (rl.pausedUntil) {
    lines.push(`  Backoff Paused Until: ${rl.pausedUntil}`);
  }

  lines.push(`  Repos (${data.config.repos.length} configured):`);
  if (data.config.repos.length === 0) {
    lines.push('    (none - service stays dormant with zero GitHub/Feishu requests)');
  } else {
    for (const r of data.config.repos) {
      const rs = data.repos[r.repo.toLowerCase()] as
        | { baselineCapturedAt?: string; lastPollStatus?: string; lastPollAt?: string }
        | undefined;
      lines.push(
        `    - ${r.repo} [enabled=${r.enabled}] creator=${r.creatorBotAppId || '(unset)'} kickoff=${r.kickoffBotAppId || '(none)'} baseline=${rs?.baselineCapturedAt ? 'yes' : 'pending'} last=${rs?.lastPollStatus ?? 'never'}`,
      );
    }
  }

  const groups = Object.values(data.prGroups) as Array<{
    repo: string;
    prNumber: number;
    status: string;
    chatId?: string;
    topNoticeSet?: boolean;
  }>;
  lines.push(`  PR Groups (${groups.length} tracked):`);
  for (const g of groups.slice(0, 15)) {
    lines.push(
      `    - ${g.repo}#${g.prNumber} status=${g.status} chatId=${g.chatId ?? '(pending)'} topNotice=${g.topNoticeSet ? 'yes' : 'no'}`,
    );
  }
  return lines.join('\n');
}

const commands = {
  'github:status': {
    description: 'Show GitHub plugin service status, rate limits, repo rules, and PR group mappings.',
    async run(ctx?: CliContext, api?: CliApi): Promise<string | number> {
      const { flags, positional } = parseFlags(ctx?.args ?? []);
      const registry = new SecretRegistry();
      let asJson = false;

      try {
        asJson = parseBooleanFlag(flags, 'json');
        assertAllowedArgs(flags, positional, { allowedFlags: ['json'], maxPositional: 0 });
        const pluginHome = await resolveCliHome(ctx, api);
        const allowInsecure = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
        const config = await loadPluginConfig(pluginHome, {
          allowInsecureLocalApiForTests: allowInsecure,
        });
        registerConfigSecrets(config, registry);
        const stateStore = new StateStore(pluginHome, registry);
        const state = await stateStore.load();

        const live = await callRunningService({
          pluginHome,
          ports: candidatePorts(state.service.boundPort, config.service.port),
          method: 'GET',
          path: '/api/status',
          timeoutMs: 2_000,
        });

        const liveObj =
          live.kind === 'ok' && live.json && typeof live.json === 'object'
            ? (live.json as Record<string, unknown>)
            : null;

        const summary = {
          online: Boolean(liveObj),
          mode:
            typeof liveObj?.mode === 'string'
              ? liveObj.mode
              : config.repos.some(r => r.enabled)
                ? state.service.mode
                : 'dormant',
          port:
            typeof liveObj?.port === 'number'
              ? liveObj.port
              : live.kind === 'ok'
                ? live.port
                : config.service.port,
          config: redactConfig(config),
          rateLimits: (liveObj?.rateLimits ?? state.rateLimits) as Record<string, unknown>,
          repos: (liveObj?.repos ?? state.repos) as Record<string, unknown>,
          prGroups: (liveObj?.prGroups ?? state.prGroups) as Record<string, unknown>,
        };

        if (asJson) {
          return JSON.stringify(summary, null, 2);
        }
        return formatStatusText(summary);
      } catch (err) {
        const safeErr = formatSafeError(err, registry);
        if (asJson) {
          console.log(JSON.stringify({ ok: false, error: safeErr }, null, 2));
        } else {
          console.error(`GitHub status FAILED: ${safeErr}`);
        }
        return 1;
      }
    },
  },

  'github:sync': {
    description: 'Trigger an immediate GitHub PR poll/sync [--repo owner/repo] [--dry-run] [--json].',
    async run(ctx?: CliContext, api?: CliApi): Promise<string | number> {
      const { flags, positional } = parseFlags(ctx?.args ?? []);
      const registry = new SecretRegistry();
      let asJson = false;

      try {
        asJson = parseBooleanFlag(flags, 'json');
        assertAllowedArgs(flags, positional, { allowedFlags: ['repo', 'dry-run', 'json'], maxPositional: 0 });
        const dryRun = parseBooleanFlag(flags, 'dry-run');
        if (flags.repo === true || (typeof flags.repo === 'string' && !flags.repo.trim())) {
          const msg = 'Missing value for --repo (expected owner/repo)';
          if (asJson) console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
          else console.error(msg);
          return 1;
        }
        const repo = typeof flags.repo === 'string' ? flags.repo.trim() : undefined;

        const pluginHome = await resolveCliHome(ctx, api);
        const allowInsecure = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
        const config = await loadPluginConfig(pluginHome, {
          allowInsecureLocalApiForTests: allowInsecure,
        });
        registerConfigSecrets(config, registry);
        const stateStore = new StateStore(pluginHome, registry);
        const state = await stateStore.load();

        let result: SyncResult;
        const live = await callRunningService({
          pluginHome,
          ports: candidatePorts(state.service.boundPort, config.service.port),
          method: 'POST',
          path: '/api/sync',
          body: { ...(repo ? { repo } : {}), dryRun, async: false },
          timeoutMs: 30_000,
        });

        if (live.kind === 'unreachable') {
          const watcher = await createInProcessWatcher(pluginHome, config, registry);
          result = await watcher.sync({ repo, dryRun });
        } else if (live.kind === 'ok' && live.json && typeof live.json === 'object') {
          result = live.json as SyncResult;
        } else {
          const msg =
            live.kind === 'timeout'
              ? `Live service timed out during sync: ${live.error}`
              : `Live service returned invalid response (HTTP ${live.status}) during sync`;
          if (asJson) {
            console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
          } else {
            console.error(`GitHub sync FAILED: ${msg}`);
          }
          return 1;
        }

        if (asJson) {
          console.log(JSON.stringify(result, null, 2));
          return result.ok ? 0 : 1;
        }

        const lines = [
          `GitHub sync ${result.ok ? 'succeeded' : 'completed with errors'} (mode=${result.mode}, dryRun=${result.dryRun})`,
        ];
        if (result.actions.length === 0) {
          lines.push('  No actions.');
        } else {
          for (const a of result.actions) {
            const target = a.prNumber ? `${a.repo}#${a.prNumber}` : a.repo;
            lines.push(
              `  - ${target}: ${a.action}${a.chatId ? ` (chatId=${a.chatId})` : ''}${a.reason ? ` [${a.reason}]` : ''}`,
            );
          }
        }
        for (const e of result.errors) {
          lines.push(`  ERROR: ${e}`);
        }
        if (!result.ok) {
          console.error(lines.join('\n'));
          return 1;
        }
        return lines.join('\n');
      } catch (err) {
        const safeErr = formatSafeError(err, registry);
        if (asJson) {
          console.log(JSON.stringify({ ok: false, error: safeErr }, null, 2));
        } else {
          console.error(`GitHub sync FAILED: ${safeErr}`);
        }
        return 1;
      }
    },
  },

  'github:open-pr': {
    description: 'Explicitly create or resume a Botmux review group for <owner/repo#N> [--dry-run] [--json].',
    async run(ctx?: CliContext, api?: CliApi): Promise<string | number> {
      const { flags, positional } = parseFlags(ctx?.args ?? []);
      const registry = new SecretRegistry();
      let asJson = false;
      let specRaw = positional[0] ?? '';

      try {
        asJson = parseBooleanFlag(flags, 'json');
        assertAllowedArgs(flags, positional, { allowedFlags: ['dry-run', 'json'], maxPositional: 1 });
        const dryRun = parseBooleanFlag(flags, 'dry-run');
        const parsed = parsePrSpec(specRaw);
        if (!parsed) {
          const msg = 'Usage: botmux github:open-pr <owner/repo#N> [--dry-run] [--json]';
          if (asJson) {
            console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
          } else {
            console.error(msg);
          }
          return 1;
        }

        const pluginHome = await resolveCliHome(ctx, api);
        const allowInsecure = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
        const config = await loadPluginConfig(pluginHome, {
          allowInsecureLocalApiForTests: allowInsecure,
        });
        registerConfigSecrets(config, registry);
        const stateStore = new StateStore(pluginHome, registry);
        const state = await stateStore.load();

        let result: OpenPrResult;
        const live = await callRunningService({
          pluginHome,
          ports: candidatePorts(state.service.boundPort, config.service.port),
          method: 'POST',
          path: '/api/open-pr',
          body: { repo: parsed.repo, prNumber: parsed.prNumber, dryRun },
          timeoutMs: 45_000,
        });

        if (live.kind === 'unreachable') {
          const watcher = await createInProcessWatcher(pluginHome, config, registry);
          result = await watcher.openPr({
            repo: parsed.repo,
            prNumber: parsed.prNumber,
            dryRun,
          });
        } else if (
          (live.kind === 'ok' || live.kind === 'http_error') &&
          live.json &&
          typeof live.json === 'object'
        ) {
          result = live.json as OpenPrResult;
        } else {
          const msg =
            live.kind === 'timeout'
              ? `Live service timed out during open-pr (${live.error}); check github:status before retrying`
              : `Live service returned empty/invalid response (HTTP ${live.status}) during open-pr; check github:status before retrying`;
          if (asJson) {
            console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
          } else {
            console.error(msg);
          }
          return 1;
        }

        if (asJson) {
          console.log(JSON.stringify(result, null, 2));
          return result.ok ? 0 : 1;
        }

        if (!result.ok) {
          console.error(`Failed to open PR ${parsed.repo}#${parsed.prNumber}: ${result.error}`);
          return 1;
        }

        const lines = [
          `${result.repo}#${result.prNumber}: ${result.action}${result.dryRun ? ' (dry-run)' : ''}`,
        ];
        if (result.groupName) lines.push(`  Group Name: ${result.groupName}`);
        if (result.chatId) lines.push(`  Chat ID: ${result.chatId}`);
        if (result.shareLink) lines.push(`  Share Link: ${result.shareLink}`);
        if (result.kickoffMessageId) {
          lines.push(
            `  Kickoff Message: ${result.kickoffMessageId} (verified=${Boolean(result.kickoffVerified)})`,
          );
        }
        if (result.topNoticeSet !== undefined) {
          lines.push(`  Top Notice Set: ${result.topNoticeSet}`);
        }
        return lines.join('\n');
      } catch (err) {
        const safeErr = formatSafeError(err, registry);
        if (asJson) {
          console.log(JSON.stringify({ ok: false, error: safeErr }, null, 2));
        } else {
          console.error(`Failed to open PR ${specRaw || '<spec>'}: ${safeErr}`);
        }
        return 1;
      }
    },
  },

  'github:test-auth': {
    description: 'Test configured GitHub authentication (PAT, GitHub App, or gh auth token) [--repo owner/repo] [--json].',
    async run(ctx?: CliContext, api?: CliApi): Promise<string | number> {
      const { flags, positional } = parseFlags(ctx?.args ?? []);
      const registry = new SecretRegistry();
      let asJson = false;

      try {
        asJson = parseBooleanFlag(flags, 'json');
        assertAllowedArgs(flags, positional, { allowedFlags: ['repo', 'json'], maxPositional: 0 });
        if (flags.repo === true || (typeof flags.repo === 'string' && !flags.repo.trim())) {
          const msg = 'Missing value for --repo (expected owner/repo)';
          if (asJson) console.log(JSON.stringify({ ok: false, error: msg }, null, 2));
          else console.error(msg);
          return 1;
        }
        const repo = typeof flags.repo === 'string' ? flags.repo.trim() : undefined;

        const pluginHome = await resolveCliHome(ctx, api);
        const allowInsecure = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
        const config = await loadPluginConfig(pluginHome, {
          allowInsecureLocalApiForTests: allowInsecure,
        });
        registerConfigSecrets(config, registry);
        const stateStore = new StateStore(pluginHome, registry);
        const state = await stateStore.load();

        let result: AuthTestResult;
        const live = await callRunningService({
          pluginHome,
          ports: candidatePorts(state.service.boundPort, config.service.port),
          method: 'POST',
          path: '/api/test-auth',
          body: { ...(repo ? { repo } : {}) },
          timeoutMs: 12_000,
        });

        if (live.kind === 'ok' && live.json && typeof live.json === 'object') {
          result = live.json as AuthTestResult;
        } else {
          const watcher = await createInProcessWatcher(pluginHome, config, registry);
          result = await watcher.testAuth({ repo, timeoutMs: 10_000 });
        }

        if (asJson) {
          console.log(JSON.stringify(result, null, 2));
          return result.ok ? 0 : 1;
        }

        if (!result.ok) {
          console.error(`GitHub auth test FAILED (${result.authMode}): ${result.error}`);
          return 1;
        }

        const lines = [
          'GitHub auth test OK',
          `  Method: ${result.resolvedMethod ?? result.authMode} (configured=${result.authMode})`,
          `  API Base: ${result.apiBaseUrl}`,
          `  Identity: ${result.identity ?? 'authenticated'}`,
        ];
        if (result.scopes && result.scopes.length > 0) {
          lines.push(`  Scopes: ${result.scopes.join(', ')}`);
        }
        if (result.rateLimit) {
          lines.push(
            `  Core Rate Limit: ${result.rateLimit.remaining}/${result.rateLimit.limit} (reset=${result.rateLimit.resetAt})`,
          );
        }
        if (result.repoAccess) {
          lines.push(
            `  Repo Access (${result.repoAccess.repo}): ${result.repoAccess.ok ? 'OK' : `FAILED (${result.repoAccess.error})`}`,
          );
        }
        return lines.join('\n');
      } catch (err) {
        const safeErr = formatSafeError(err, registry);
        if (asJson) {
          console.log(JSON.stringify({ ok: false, error: safeErr }, null, 2));
        } else {
          console.error(`GitHub auth test FAILED: ${safeErr}`);
        }
        return 1;
      }
    },
  },
};

export default commands;
