import type { LarkBrand, ProxyConfig } from '../types.ts';
import {
  parseProxyStateFailClosed,
  secureOutboundRequest,
  isTestLoopbackApiAllowed,
  type ProxyState,
} from '../security/net.ts';
import { SecretRegistry, defaultSecretRegistry, formatSafeError } from '../security/redact.ts';

export const FEISHU_OPEN_API_BASE = 'https://open.feishu.cn';
export const LARK_OPEN_API_BASE = 'https://open.larksuite.com';

const CHAT_ID_RE = /^oc_[A-Za-z0-9_-]{1,128}$/;
const MESSAGE_ID_RE = /^om_[A-Za-z0-9_-]{1,128}$/;

export function getLarkOpenApiOrigin(
  brand: LarkBrand,
  testOriginOverrides?: Partial<Record<LarkBrand, string>>,
): string {
  if (testOriginOverrides?.[brand] && isTestLoopbackApiAllowed(true)) {
    return testOriginOverrides[brand]!.replace(/\/+$/, '');
  }
  return brand === 'lark' ? LARK_OPEN_API_BASE : FEISHU_OPEN_API_BASE;
}

export function normalizeTrustedLarkShareLink(url: string): string | null {
  if (typeof url !== 'string') return null;
  const trimmed = url.trim();
  // Reject control chars, newlines, tabs, whitespace BEFORE new URL() (WHATWG URL strips CR/LF/TAB!)
  if (!trimmed || /[\r\n\t\x00-\x1f\x7f\s<>]/.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'https:') return null;
    const host = parsed.hostname.toLowerCase();
    const trusted =
      host === 'applink.feishu.cn' ||
      host === 'applink.larksuite.com' ||
      host.endsWith('.feishu.cn') ||
      host.endsWith('.larksuite.com') ||
      host.endsWith('.larkoffice.com');
    return trusted ? parsed.toString() : null;
  } catch {
    return null;
  }
}

export function isTrustedLarkShareLink(url: string): boolean {
  return normalizeTrustedLarkShareLink(url) !== null;
}

interface CachedTenantToken {
  token: string;
  expiresAtMs: number;
}

/**
 * Brand-aware Feishu / Lark Open Platform client used exclusively as a fallback
 * when the Botmux daemon IPC does not yet expose POST /api/groups/:chatId/top-notice.
 * Strictly NEVER invokes `lark-cli --as user`.
 */
export class LarkOpenApiClient {
  private readonly proxyState: ProxyState;
  private readonly registry: SecretRegistry;
  private readonly testOriginOverrides?: Partial<Record<LarkBrand, string>>;
  private readonly now: () => number;
  private readonly tokenCache = new Map<string, CachedTenantToken>();

  constructor(opts?: {
    proxy?: ProxyConfig;
    registry?: SecretRegistry;
    testOriginOverrides?: Partial<Record<LarkBrand, string>>;
    now?: () => number;
  }) {
    this.registry = opts?.registry ?? defaultSecretRegistry;
    this.proxyState = parseProxyStateFailClosed(
      opts?.proxy?.url,
      { username: opts?.proxy?.username, password: opts?.proxy?.password },
      this.registry,
    );
    this.testOriginOverrides = opts?.testOriginOverrides;
    this.now = opts?.now ?? (() => Date.now());
  }

  async getTenantAccessToken(
    appId: string,
    appSecret: string,
    brand: LarkBrand,
  ): Promise<string> {
    this.registry.register(appSecret);
    const cacheKey = `${brand}:${appId}`;
    const cached = this.tokenCache.get(cacheKey);
    const marginMs = 5 * 60 * 1000;
    if (cached && this.now() + marginMs < cached.expiresAtMs) {
      return cached.token;
    }

    const origin = getLarkOpenApiOrigin(brand, this.testOriginOverrides);
    const url = new URL(`${origin}/open-apis/auth/v3/tenant_access_token/internal`);
    const isLocalTest = Boolean(this.testOriginOverrides?.[brand]);

    const res = await secureOutboundRequest({
      url,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'botmux-plugin-github',
      },
      body: Buffer.from(JSON.stringify({ app_id: appId, app_secret: appSecret }), 'utf8'),
      proxy: isLocalTest ? { kind: 'direct' } : this.proxyState,
      allowPrivateIntranet: isLocalTest,
      allowedOrigin: url.origin,
      skipIpBlockCheck: isLocalTest,
      timeoutMs: 15_000,
      maxResponseBytes: 1024 * 1024,
    });

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Lark tenant_access_token HTTP ${res.status}`);
    }

    const parsed = JSON.parse(res.body.toString('utf8')) as {
      code?: number;
      msg?: string;
      tenant_access_token?: string;
      expire?: number;
    };
    if (parsed.code !== 0 || !parsed.tenant_access_token) {
      throw new Error(
        `Lark tenant_access_token error (${parsed.code ?? 'unknown'}): ${this.registry.redactString(parsed.msg ?? 'failed')}`,
      );
    }

    this.registry.register(parsed.tenant_access_token);
    const expireSec = typeof parsed.expire === 'number' && parsed.expire > 0 ? parsed.expire : 7200;
    this.tokenCache.set(cacheKey, {
      token: parsed.tenant_access_token,
      expiresAtMs: this.now() + expireSec * 1000,
    });
    return parsed.tenant_access_token;
  }

  /**
   * Pins a message as the chat top notice via Feishu/Lark Open Platform API:
   * POST /open-apis/im/v1/chats/:chat_id/top_notice/put_top_notice
   * with `{ chat_top_notice: [{ action_type: "1", message_id }] }`.
   */
  async putChatTopNotice(opts: {
    appId: string;
    appSecret: string;
    brand: LarkBrand;
    chatId: string;
    messageId: string;
  }): Promise<{ ok: true } | { ok: false; error: string }> {
    if (!CHAT_ID_RE.test(opts.chatId)) {
      return { ok: false, error: `Invalid chatId for top notice: ${opts.chatId}` };
    }
    if (!MESSAGE_ID_RE.test(opts.messageId)) {
      return { ok: false, error: `Invalid messageId for top notice: ${opts.messageId}` };
    }

    try {
      const tenantToken = await this.getTenantAccessToken(
        opts.appId,
        opts.appSecret,
        opts.brand,
      );
      const origin = getLarkOpenApiOrigin(opts.brand, this.testOriginOverrides);
      const url = new URL(
        `${origin}/open-apis/im/v1/chats/${encodeURIComponent(opts.chatId)}/top_notice/put_top_notice`,
      );
      const isLocalTest = Boolean(this.testOriginOverrides?.[opts.brand]);

      const res = await secureOutboundRequest({
        url,
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tenantToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'botmux-plugin-github',
        },
        body: Buffer.from(
          JSON.stringify({
            chat_top_notice: [
              {
                action_type: '1',
                message_id: opts.messageId,
              },
            ],
          }),
          'utf8',
        ),
        proxy: isLocalTest ? { kind: 'direct' } : this.proxyState,
        allowPrivateIntranet: isLocalTest,
        allowedOrigin: url.origin,
        skipIpBlockCheck: isLocalTest,
        timeoutMs: 15_000,
        maxResponseBytes: 1024 * 1024,
      });

      if (res.status < 200 || res.status >= 300) {
        return {
          ok: false,
          error: `Lark put_top_notice HTTP ${res.status}`,
        };
      }

      const parsed = JSON.parse(res.body.toString('utf8')) as { code?: number; msg?: string };
      if (parsed.code !== 0) {
        return {
          ok: false,
          error: `Lark put_top_notice failed (${parsed.code ?? 'unknown'}): ${this.registry.redactString(parsed.msg ?? 'error')}`,
        };
      }
      return { ok: true };
    } catch (err) {
      return {
        ok: false,
        error: formatSafeError(err, this.registry),
      };
    }
  }
}
