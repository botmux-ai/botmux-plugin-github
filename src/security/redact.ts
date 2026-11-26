const TOKEN_REDACTED = '[REDACTED]';

// Order matters: match multiline/escaped/truncated PEM keys and structured headers before shorter tokens.
const PEM_FULL_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const PEM_ESCAPED_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\n|\\r\\n|[A-Za-z0-9+/=\s]){8,}(?:-----END [A-Z0-9 ]*PRIVATE KEY-----)?/g;
const PEM_TRUNCATED_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*/g;
const GITHUB_CLASSIC_RE = /\bgh[opsur]_[A-Za-z0-9_]{16,255}\b/g;
const GITHUB_PAT_RE = /\bgithub_pat_[A-Za-z0-9_]{16,255}\b/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const AUTH_HEADER_RE =
  /\b((?:Proxy-)?Authorization\s*[:=]\s*(?:Bearer|Basic|token)\s+)[^\s"',;}\]]+/gi;
const BEARER_OR_BASIC_RE = /\b((?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{12,}/gi;
// Match URL userinfo up to the LAST '@' in the authority segment (handles passwords containing '@')
const URL_USERINFO_RE = /\b([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^\s/?#]+)@(?=[^\s/?#@]+)/g;
const FEISHU_TENANT_TOKEN_RE = /\bt-[A-Za-z0-9._-]{16,}\b/g;
const KV_SECRET_RE =
  /("(?:pat|privateKeyPem|larkAppSecret|webhookSecret|secret|password|tenant_access_token|access_token|token)"\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")/gi;

export function scrubSecrets(input: string): string {
  if (!input) return input;
  return input
    .replace(PEM_FULL_RE, TOKEN_REDACTED)
    .replace(PEM_ESCAPED_RE, TOKEN_REDACTED)
    .replace(PEM_TRUNCATED_RE, TOKEN_REDACTED)
    .replace(GITHUB_CLASSIC_RE, TOKEN_REDACTED)
    .replace(GITHUB_PAT_RE, TOKEN_REDACTED)
    .replace(JWT_RE, TOKEN_REDACTED)
    .replace(AUTH_HEADER_RE, `$1${TOKEN_REDACTED}`)
    .replace(BEARER_OR_BASIC_RE, `$1${TOKEN_REDACTED}`)
    .replace(URL_USERINFO_RE, `$1${TOKEN_REDACTED}@`)
    .replace(FEISHU_TENANT_TOKEN_RE, TOKEN_REDACTED)
    .replace(KV_SECRET_RE, `$1${TOKEN_REDACTED}$3`);
}

/**
 * Redacts credentials embedded in a proxy URL string, even if the URL is
 * malformed or contains special characters like '/', '?', '#', or '%zz'.
 */
export function redactProxyUrl(raw: string): string {
  const trimmed = raw.trim();
  const at = trimmed.lastIndexOf('@');
  if (at < 0) return scrubSecrets(trimmed);
  const schemeMatch = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.exec(trimmed.slice(0, at));
  const prefix = schemeMatch ? schemeMatch[0] : '';
  return scrubSecrets(`${prefix}${TOKEN_REDACTED}${trimmed.slice(at)}`);
}

export class SecretRegistry {
  private readonly exact = new Set<string>();
  private sortedCache: string[] | null = null;

  register(secret: string | null | undefined): void {
    if (!secret || typeof secret !== 'string') return;
    const trimmed = secret.trim();
    if (trimmed.length < 6) return;
    this.addVariant(trimmed);
    const encoded = encodeURIComponent(trimmed);
    if (encoded !== trimmed && encoded.length >= 6) {
      this.addVariant(encoded);
    }
    const b64 = Buffer.from(trimmed, 'utf8').toString('base64');
    if (b64.length >= 8) {
      this.addVariant(b64);
    }
    // Also register JSON-escaped single-line representation for PEM keys.
    if (trimmed.includes('\n')) {
      const jsonEscaped = trimmed.replace(/\r?\n/g, '\\n');
      this.addVariant(jsonEscaped);
      const lines = trimmed
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l.length >= 16 && !l.startsWith('-----'));
      for (const line of lines) {
        this.addVariant(line);
      }
    }
  }

  registerBasicPair(username: string | undefined, password: string | undefined): void {
    if (!password) return;
    this.register(password);
    const pair = `${username ?? ''}:${password}`;
    this.addVariant(Buffer.from(pair, 'utf8').toString('base64'));
  }

  clear(): void {
    this.exact.clear();
    this.sortedCache = null;
  }

  private addVariant(v: string): void {
    if (!this.exact.has(v)) {
      this.exact.add(v);
      this.sortedCache = null;
    }
  }

  private getSortedSecrets(): string[] {
    if (!this.sortedCache) {
      this.sortedCache = Array.from(this.exact).sort((a, b) => b.length - a.length);
    }
    return this.sortedCache;
  }

  redactString(input: string): string {
    if (!input) return input;
    let out = input;
    for (const secret of this.getSortedSecrets()) {
      if (out.includes(secret)) {
        out = out.split(secret).join(TOKEN_REDACTED);
      }
    }
    return scrubSecrets(out);
  }

  redactUnknown(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') return this.redactString(value);
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'bigint') return value.toString();
    if (typeof value === 'symbol' || typeof value === 'function') return undefined;

    if (depth > 8) return '[MaxDepth]';

    if (value instanceof URL) {
      return redactProxyUrl(value.toString());
    }
    if (Buffer.isBuffer(value)) {
      return this.redactString(value.toString('utf8'));
    }
    if (value instanceof Error) {
      const safeErr: Record<string, unknown> = {
        name: value.name,
        message: this.redactString(value.message),
      };
      const code = (value as { code?: unknown }).code;
      if (typeof code === 'string' || typeof code === 'number') {
        safeErr.code = code;
      }
      if (typeof value.stack === 'string') {
        safeErr.stack = this.redactString(value.stack);
      }
      if ('cause' in value && (value as { cause?: unknown }).cause !== undefined) {
        safeErr.cause = this.redactUnknown((value as { cause?: unknown }).cause, depth + 1, seen);
      }
      return safeErr;
    }

    if (typeof value === 'object') {
      if (seen.has(value)) return '[Circular]';
      seen.add(value);
      if (Array.isArray(value)) {
        return value.map(item => this.redactUnknown(item, depth + 1, seen));
      }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        const lower = k.toLowerCase();
        if (
          lower === 'pat' ||
          lower === 'privatekeypem' ||
          lower === 'larkappsecret' ||
          lower === 'webhooksecret' ||
          lower === 'authorization' ||
          lower === 'proxy-authorization' ||
          lower === 'password'
        ) {
          out[k] = v ? TOKEN_REDACTED : v;
        } else {
          out[k] = this.redactUnknown(v, depth + 1, seen);
        }
      }
      return out;
    }

    return String(value);
  }

  assertNoSecrets(serialized: string): void {
    for (const secret of this.getSortedSecrets()) {
      if (serialized.includes(secret)) {
        throw new Error('Refused to persist data containing a registered secret');
      }
    }
    if (
      GITHUB_CLASSIC_RE.test(serialized) ||
      GITHUB_PAT_RE.test(serialized) ||
      PEM_TRUNCATED_RE.test(serialized)
    ) {
      // Reset regex lastIndex before throwing
      GITHUB_CLASSIC_RE.lastIndex = 0;
      GITHUB_PAT_RE.lastIndex = 0;
      PEM_TRUNCATED_RE.lastIndex = 0;
      throw new Error('Refused to persist data matching a secret token pattern');
    }
    GITHUB_CLASSIC_RE.lastIndex = 0;
    GITHUB_PAT_RE.lastIndex = 0;
    PEM_TRUNCATED_RE.lastIndex = 0;
  }
}

export const defaultSecretRegistry = new SecretRegistry();

export function formatSafeError(err: unknown, registry: SecretRegistry = defaultSecretRegistry): string {
  if (err instanceof Error) {
    const code = (err as { code?: unknown }).code;
    const prefix = typeof code === 'string' ? `[${code}] ` : '';
    return registry.redactString(`${prefix}${err.message}`);
  }
  return registry.redactString(String(err));
}
