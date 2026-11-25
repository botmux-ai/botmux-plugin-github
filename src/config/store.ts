import os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { PluginConfig } from '../types.ts';
import { PLUGIN_ID } from '../types.ts';
import {
  acquireSecureLock,
  ensureSecureDir,
  readSecureFileIfExists,
  writeSecureFileAtomic,
} from '../security/fs.ts';
import { createDefaultConfig, normalizeAndValidateConfig } from './schema.ts';

const MAX_CONFIG_BYTES = 1024 * 1024; // 1 MiB

export function resolvePluginHome(opts?: {
  pluginHome?: string;
  configPath?: string;
}): string {
  if (opts?.pluginHome && opts.pluginHome.trim()) {
    return resolve(opts.pluginHome.trim());
  }
  if (opts?.configPath && opts.configPath.trim()) {
    return dirname(resolve(opts.configPath.trim()));
  }
  const envHome = process.env.BOTMUX_PLUGIN_HOME?.trim();
  if (envHome) {
    return resolve(envHome);
  }
  return join(os.homedir(), '.botmux', 'plugins', PLUGIN_ID);
}

export function getConfigPath(pluginHome: string): string {
  return join(resolve(pluginHome), 'config.json');
}

export function getControlTokenPath(pluginHome: string): string {
  return join(resolve(pluginHome), 'private', 'control.token');
}

export async function loadPluginConfig(
  pluginHome: string,
  opts?: { allowInsecureLocalApiForTests?: boolean },
): Promise<PluginConfig> {
  const cfgPath = getConfigPath(pluginHome);
  const raw = await readSecureFileIfExists(cfgPath, {
    maxBytes: MAX_CONFIG_BYTES,
    requireMode0600: true,
  });
  if (!raw) {
    return createDefaultConfig();
  }
  const parsed: unknown = JSON.parse(raw.toString('utf8'));
  return normalizeAndValidateConfig(parsed, opts);
}

export async function savePluginConfig(
  pluginHome: string,
  config: PluginConfig,
  opts?: { allowInsecureLocalApiForTests?: boolean },
): Promise<PluginConfig> {
  const validated = normalizeAndValidateConfig(config, opts);
  const cfgPath = getConfigPath(pluginHome);
  const lockPath = join(resolve(pluginHome), '.config.lock');
  await ensureSecureDir(pluginHome);
  const lock = await acquireSecureLock(lockPath);
  try {
    await writeSecureFileAtomic(cfgPath, `${JSON.stringify(validated, null, 2)}\n`);
    return validated;
  } finally {
    await lock.release();
  }
}

/**
 * Loads or generates the 0600 per-plugin local control token stored in
 * `$BOTMUX_PLUGIN_HOME/private/control.token` used to authenticate local
 * loopback control requests (/api/status, /api/reload, /api/sync, /api/open-pr).
 */
export async function ensureControlToken(pluginHome: string): Promise<string> {
  // Always validate pluginHome itself first so symlinked pluginHome is rejected
  await ensureSecureDir(pluginHome);
  const tokenPath = getControlTokenPath(pluginHome);
  const existing = await readSecureFileIfExists(tokenPath, {
    maxBytes: 1024,
    requireMode0600: true,
  });
  if (existing) {
    const trimmed = existing.toString('utf8').trim();
    if (trimmed.length >= 32) {
      return trimmed;
    }
  }
  await ensureSecureDir(dirname(tokenPath));
  const token = randomBytes(32).toString('base64url');
  await writeSecureFileAtomic(tokenPath, `${token}\n`);
  return token;
}

export async function readControlTokenIfExists(pluginHome: string): Promise<string | null> {
  const tokenPath = getControlTokenPath(pluginHome);
  const existing = await readSecureFileIfExists(tokenPath, {
    maxBytes: 1024,
    requireMode0600: true,
  });
  if (!existing) return null;
  const trimmed = existing.toString('utf8').trim();
  return trimmed.length >= 32 ? trimmed : null;
}
