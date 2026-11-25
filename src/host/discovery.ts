import os from 'node:os';
import { promises as fsp } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { BotConfigEntry, BotsInfoEntry, DaemonDescriptor, LarkBrand } from '../types.ts';
import { readSecureFileIfExists } from '../security/fs.ts';
import { SecretRegistry, defaultSecretRegistry } from '../security/redact.ts';

const DAEMON_HEARTBEAT_STALE_MS = 90_000;
const HMAC_WINDOW_SEC = 30;

export interface DiscoveryOptions {
  botmuxHome?: string;
  dataDir?: string;
  botsConfigPath?: string;
  botmuxBin?: string;
  now?: () => number;
}

export function resolveBotmuxHome(opts?: DiscoveryOptions): string {
  if (opts?.botmuxHome?.trim()) return resolve(opts.botmuxHome.trim());
  if (process.env.BOTMUX_HOME?.trim()) return resolve(process.env.BOTMUX_HOME.trim());
  return join(os.homedir(), '.botmux');
}

/**
 * Resolves Botmux data directory matching Botmux core precedence + BOTMUX_DATA_DIR:
 * 1. Explicit opts.dataDir
 * 2. process.env.BOTMUX_DATA_DIR
 * 3. process.env.SESSION_DATA_DIR
 * 4. ~/.botmux/.data-dir breadcrumb (regular non-symlink <= 4096 bytes containing existing abs dir)
 * 5. ~/.botmux/data
 */
export async function resolveBotmuxDataDir(opts?: DiscoveryOptions): Promise<string> {
  if (opts?.dataDir?.trim()) return resolve(opts.dataDir.trim());
  if (process.env.BOTMUX_DATA_DIR?.trim()) return resolve(process.env.BOTMUX_DATA_DIR.trim());
  if (process.env.SESSION_DATA_DIR?.trim()) return resolve(process.env.SESSION_DATA_DIR.trim());

  const home = resolveBotmuxHome(opts);
  const breadcrumbPath = join(home, '.data-dir');
  try {
    const raw = await readSecureFileIfExists(breadcrumbPath, {
      maxBytes: 4096,
      rejectHardlinks: false,
    });
    if (raw) {
      const candidate = raw.toString('utf8').trim();
      if (candidate && isAbsolute(candidate)) {
        const st = await fsp.lstat(candidate).catch(() => null);
        const uid = typeof process.getuid === 'function' ? process.getuid() : null;
        if (st && !st.isSymbolicLink() && st.isDirectory() && (uid === null || st.uid === uid)) {
          return candidate;
        }
      }
    }
  } catch {
    // Fall back to default data dir
  }

  return join(home, 'data');
}

export function resolveBotmuxBin(opts?: DiscoveryOptions): string {
  if (opts?.botmuxBin?.trim()) return opts.botmuxBin.trim();
  if (process.env.BOTMUX_BIN?.trim()) return process.env.BOTMUX_BIN.trim();
  return 'botmux';
}

export function normalizeBrand(raw: unknown): LarkBrand {
  return raw === 'lark' ? 'lark' : 'feishu';
}

/**
 * Reads bots.json from BOTS_CONFIG (fail-closed if set and missing) or ~/.botmux/bots.json.
 * Registers all larkAppSecret values in SecretRegistry immediately.
 */
export async function loadBotsConfig(
  opts?: DiscoveryOptions,
  registry: SecretRegistry = defaultSecretRegistry,
): Promise<BotConfigEntry[]> {
  const explicitPath = opts?.botsConfigPath?.trim();
  const envPath = opts?.botmuxHome?.trim() ? undefined : process.env.BOTS_CONFIG?.trim();
  const mustExistPath = explicitPath || envPath;
  const cfgPath = mustExistPath
    ? resolve(mustExistPath)
    : join(resolveBotmuxHome(opts), 'bots.json');

  const buf = await readSecureFileIfExists(cfgPath, {
    maxBytes: 1024 * 1024,
    rejectHardlinks: false,
  });
  if (!buf) {
    if (mustExistPath) {
      throw new Error(`BOTS_CONFIG file not found: ${cfgPath}`);
    }
    return [];
  }
  const rawText = buf.toString('utf8');

  const parsed: unknown = JSON.parse(rawText);
  if (!Array.isArray(parsed)) return [];
  const entries: BotConfigEntry[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== 'object') continue;
    const obj = item as Record<string, unknown>;
    const larkAppId = typeof obj.larkAppId === 'string' ? obj.larkAppId.trim() : '';
    if (!larkAppId) continue;
    const larkAppSecret =
      typeof obj.larkAppSecret === 'string' && obj.larkAppSecret.trim()
        ? obj.larkAppSecret.trim()
        : undefined;
    if (larkAppSecret) {
      registry.register(larkAppSecret);
    }
    entries.push({
      larkAppId,
      ...(larkAppSecret ? { larkAppSecret } : {}),
      brand: normalizeBrand(obj.brand),
      ...(typeof obj.cliId === 'string' ? { cliId: obj.cliId } : {}),
      ...(typeof obj.name === 'string' ? { name: obj.name } : {}),
      ...(typeof obj.displayName === 'string' ? { displayName: obj.displayName } : {}),
      ...(obj.apiOnly === true ? { apiOnly: true } : {}),
      ...(Array.isArray(obj.allowedUsers)
        ? {
            allowedUsers: obj.allowedUsers.filter(
              (u): u is string => typeof u === 'string' && u.trim().length > 0,
            ),
          }
        : {}),
    });
  }
  return entries;
}

export async function loadBotsInfo(opts?: DiscoveryOptions): Promise<BotsInfoEntry[]> {
  const dataDir = await resolveBotmuxDataDir(opts);
  const filePath = join(dataDir, 'bots-info.json');
  try {
    const buf = await readSecureFileIfExists(filePath, {
      maxBytes: 1024 * 1024,
      rejectHardlinks: false,
    });
    if (!buf) return [];
    const parsed: unknown = JSON.parse(buf.toString('utf8'));
    if (!Array.isArray(parsed)) return [];
    const out: BotsInfoEntry[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== 'object') continue;
      const obj = item as Record<string, unknown>;
      const larkAppId = typeof obj.larkAppId === 'string' ? obj.larkAppId.trim() : '';
      const botOpenId = typeof obj.botOpenId === 'string' ? obj.botOpenId.trim() : '';
      const botName = typeof obj.botName === 'string' ? obj.botName.trim() : '';
      if (!larkAppId) continue;
      out.push({
        larkAppId,
        botOpenId,
        botName,
        ...(typeof obj.cliId === 'string' ? { cliId: obj.cliId } : {}),
      });
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Loads creator-scoped bot open_ids from `<dataDir>/bot-openids-<creatorLarkAppId>.json`
 * (keyed by trimmed botName, matching Botmux core's cross-app mention resolver).
 */
export async function loadCreatorScopedBotOpenIds(
  creatorLarkAppId: string,
  opts?: DiscoveryOptions,
): Promise<Record<string, string>> {
  const dataDir = await resolveBotmuxDataDir(opts);
  const filePath = join(dataDir, `bot-openids-${creatorLarkAppId}.json`);
  try {
    const buf = await readSecureFileIfExists(filePath, {
      maxBytes: 512 * 1024,
      rejectHardlinks: false,
    });
    if (!buf) return {};
    const parsed: unknown = JSON.parse(buf.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out = Object.create(null) as Record<string, string>;
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (typeof v === 'string' && v.trim()) {
        out[k.trim()] = v.trim();
      }
    }
    return out;
  } catch {
    return {};
  }
}

/**
 * Discovers online Botmux daemon descriptors from `<dataDir>/dashboard-daemons/*.json`.
 * Only descriptors with valid ipcPort (1..65535) and fresh heartbeat (<= 90s) are returned.
 */
export async function discoverOnlineDaemons(
  opts?: DiscoveryOptions,
): Promise<Map<string, DaemonDescriptor>> {
  const dataDir = await resolveBotmuxDataDir(opts);
  const daemonsDir = join(dataDir, 'dashboard-daemons');
  const nowMs = opts?.now ? opts.now() : Date.now();
  const result = new Map<string, DaemonDescriptor>();

  let files: string[];
  try {
    files = await fsp.readdir(daemonsDir);
  } catch {
    return result;
  }

  for (const name of files) {
    if (!name.endsWith('.json')) continue;
    const fullPath = join(daemonsDir, name);
    try {
      const buf = await readSecureFileIfExists(fullPath, {
        maxBytes: 256 * 1024,
        rejectHardlinks: false,
      });
      if (!buf) continue;
      const obj = JSON.parse(buf.toString('utf8')) as Record<string, unknown>;
      const larkAppId = typeof obj.larkAppId === 'string' ? obj.larkAppId.trim() : '';
      const ipcPort = typeof obj.ipcPort === 'number' ? obj.ipcPort : NaN;
      const lastHeartbeat = typeof obj.lastHeartbeat === 'number' ? obj.lastHeartbeat : 0;
      if (!larkAppId) continue;
      if (!Number.isSafeInteger(ipcPort) || ipcPort < 1 || ipcPort > 65535) continue;
      if (nowMs - lastHeartbeat > DAEMON_HEARTBEAT_STALE_MS) continue;

      const resolvedAllowedUsers = Array.isArray(obj.resolvedAllowedUsers)
        ? obj.resolvedAllowedUsers.filter(
            (u): u is string => typeof u === 'string' && u.trim().length > 0,
          )
        : [];

      result.set(larkAppId, {
        larkAppId,
        ipcPort,
        lastHeartbeat,
        resolvedAllowedUsers,
        ...(typeof obj.botName === 'string' ? { botName: obj.botName } : {}),
        ...(typeof obj.cliId === 'string' ? { cliId: obj.cliId } : {}),
        ...(typeof obj.pid === 'number' ? { pid: obj.pid } : {}),
      });
    } catch {
      // Ignore malformed/stale descriptor
    }
  }
  return result;
}

/**
 * Loads ~/.botmux/.dashboard-secret (regular non-symlink 0600 file).
 */
export async function loadDashboardSecret(
  opts?: DiscoveryOptions,
  registry: SecretRegistry = defaultSecretRegistry,
): Promise<string | null> {
  const secretPath = join(resolveBotmuxHome(opts), '.dashboard-secret');
  try {
    const raw = await readSecureFileIfExists(secretPath, {
      maxBytes: 4096,
      rejectHardlinks: false,
    });
    if (!raw) return null;
    const trimmed = raw.toString('utf8').trim();
    if (!trimmed) return null;
    registry.register(trimmed);
    return trimmed;
  } catch {
    return null;
  }
}

/**
 * Signs a Botmux daemon IPC request using exact Botmux daemon-ipc-auth contract:
 * - ts: UNIX SECONDS
 * - nonce: fresh 8-byte hex
 * - bind: `${METHOD} ${pathnameWithoutQuery} ${port}`
 * - sig: HMAC-SHA256(secret, `${ts}:${nonce}:${bind}`).digest('base64url')
 */
export function signDaemonIpcHeaders(
  secret: string,
  method: string,
  pathWithQuery: string,
  port: number,
  nowMs = Date.now(),
): Record<string, string> {
  const ts = Math.floor(nowMs / 1000).toString();
  const nonce = randomBytes(8).toString('hex');
  const pathname = new URL(pathWithQuery, `http://127.0.0.1:${port}`).pathname;
  const bind = `${method.toUpperCase()} ${pathname} ${port}`;
  const sig = createHmac('sha256', secret).update(`${ts}:${nonce}:${bind}`).digest('base64url');
  return {
    'X-Botmux-Cli-Ts': ts,
    'X-Botmux-Cli-Nonce': nonce,
    'X-Botmux-Cli-Auth': sig,
  };
}

/**
 * Verifies Botmux daemon-style HMAC headers on incoming loopback control requests.
 */
export function verifyDaemonIpcHeaders(
  headers: Record<string, string | string[] | undefined>,
  secret: string,
  method: string,
  pathWithQuery: string,
  port: number,
  seenNonces: Map<string, number>,
  nowMs = Date.now(),
): boolean {
  const getSingle = (key: string): string | null => {
    const v = headers[key.toLowerCase()];
    if (typeof v !== 'string') return null;
    return v.trim() || null;
  };

  const tsRaw = getSingle('x-botmux-cli-ts');
  const nonce = getSingle('x-botmux-cli-nonce');
  const auth = getSingle('x-botmux-cli-auth');
  if (!tsRaw || !nonce || !auth) return false;
  if (!/^\d+$/.test(tsRaw) || !/^[A-Za-z0-9_-]{8,64}$/.test(nonce)) return false;

  const tsSec = Number.parseInt(tsRaw, 10);
  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - tsSec) > HMAC_WINDOW_SEC) return false;

  // Prune expired nonces and reject replays
  for (const [k, exp] of seenNonces.entries()) {
    if (exp <= nowMs) seenNonces.delete(k);
  }
  if (seenNonces.has(nonce)) return false;

  const pathname = new URL(pathWithQuery, `http://127.0.0.1:${port}`).pathname;
  const bind = `${method.toUpperCase()} ${pathname} ${port}`;
  const expected = createHmac('sha256', secret).update(`${tsRaw}:${nonce}:${bind}`).digest('base64url');

  const a = Buffer.from(auth, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;

  seenNonces.set(nonce, nowMs + HMAC_WINDOW_SEC * 2 * 1000);
  return true;
}
