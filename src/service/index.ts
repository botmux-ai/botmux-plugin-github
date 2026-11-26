import { DEFAULT_SERVICE_PORT } from '../types.ts';

interface ServiceConfigApi {
  get?<T = unknown>(key?: string): T | undefined;
}

interface ServiceFactoryApi {
  config?: ServiceConfigApi;
}

export interface PluginServiceDefinition {
  mode: 'auto';
  port: number;
  pm2: {
    script: string;
    env: Record<string, string>;
    autorestart: boolean;
    killTimeoutMs: number;
    watchDelayMs: number;
  };
  urls(ctx: { host: string; env: Record<string, string>; port?: number }): {
    openUrl: string;
    healthUrl: string;
  };
}

function parsePort(raw: unknown): number | null {
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && raw.trim() ? Number(raw.trim()) : NaN;
  if (Number.isInteger(n) && n >= 1 && n <= 65535) return n;
  return null;
}

/**
 * Default factory function exported by dist/service/index.js.
 * Using a factory function ensures Botmux's long-lived Dashboard process always
 * resolves the live configured port on every start/stop/restart/status call
 * (since Botmux imports service/index.js without a query-string cache-buster).
 */
export default function createGitHubServiceDefinition(
  api?: ServiceFactoryApi,
): PluginServiceDefinition {
  const configuredPort =
    parsePort(api?.config?.get?.('service.port')) ??
    parsePort(process.env.BOTMUX_GITHUB_PORT) ??
    DEFAULT_SERVICE_PORT;

  return {
    mode: 'auto',
    port: configuredPort,
    pm2: {
      script: './service/runner.js',
      env: {
        PORT: String(configuredPort),
        BOTMUX_GITHUB_PORT: String(configuredPort),
      },
      autorestart: true,
      killTimeoutMs: 10_000,
      watchDelayMs: 2_000,
    },
    urls({ host, port }) {
      const effectivePort = parsePort(port) ?? configuredPort;
      return {
        openUrl: `http://${host}:${effectivePort}/`,
        healthUrl: `http://${host}:${effectivePort}/health`,
      };
    },
  };
}
