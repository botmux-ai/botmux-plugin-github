import { createHash, createPrivateKey, createPublicKey, createSign } from 'node:crypto';
import { execFile } from 'node:child_process';
import type { GitHubAuthConfig } from '../types.ts';
import type { ProxyState } from '../security/net.ts';
import { secureOutboundRequest, validateGitHubApiBaseUrl } from '../security/net.ts';
import { SecretRegistry, defaultSecretRegistry } from '../security/redact.ts';
import { GH_HOSTNAME_RE } from '../config/schema.ts';

export interface ResolvedToken {
  token: string;
  method: 'pat' | 'github_app' | 'gh_cli';
  principalFingerprint: string;
  expiresAtMs?: number;
}

export class GitHubAuthError extends Error {
  readonly code = 'GITHUB_AUTH_ERROR';
  constructor(message: string) {
    super(message);
    this.name = 'GitHubAuthError';
  }
}

export interface GhCliRunner {
  (hostname?: string): Promise<string>;
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Generates an RS256 GitHub App JWT using pure node:crypto (zero dependencies).
 * iat is set 60 seconds in the past to tolerate clock skew; exp is 9 minutes ahead.
 */
export function createGitHubAppJwt(
  appId: string,
  privateKeyPem: string,
  nowSec = Math.floor(Date.now() / 1000),
): string {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(
    JSON.stringify({
      iat: nowSec - 60,
      exp: nowSec + 540, // 9 minutes (< GitHub's 10-minute max)
      iss: appId,
    }),
  );
  const signingInput = `${header}.${payload}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKeyPem).toString('base64url');
  return `${signingInput}.${signature}`;
}

export function defaultGhCliRunner(hostname?: string): Promise<string> {
  const args = ['auth', 'token'];
  if (hostname) {
    if (!GH_HOSTNAME_RE.test(hostname)) {
      return Promise.reject(new GitHubAuthError(`Invalid gh hostname: "${hostname}"`));
    }
    args.push('--hostname', hostname);
  }
  return new Promise((resolvePromise, reject) => {
    execFile(
      'gh',
      args,
      {
        shell: false,
        timeout: 15_000,
        maxBuffer: 64 * 1024,
        env: {
          PATH: process.env.PATH ?? '',
          HOME: process.env.HOME ?? '',
          USER: process.env.USER ?? '',
          XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME ?? '',
          GH_CONFIG_DIR: process.env.GH_CONFIG_DIR ?? '',
          GH_TOKEN: process.env.GH_TOKEN ?? '',
          GITHUB_TOKEN: process.env.GITHUB_TOKEN ?? '',
          GH_PROMPT_DISABLED: '1',
          NO_COLOR: '1',
        },
      },
      (err, stdout) => {
        if (err) {
          reject(
            new GitHubAuthError(
              `Failed to obtain token via gh auth token: ${err.message}`,
            ),
          );
          return;
        }
        const token = stdout.trim();
        if (!token) {
          reject(new GitHubAuthError('gh auth token returned empty output'));
          return;
        }
        resolvePromise(token);
      },
    );
  });
}

function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export class GitHubAuthManager {
  private readonly auth: GitHubAuthConfig;
  private readonly proxy: ProxyState;
  private readonly registry: SecretRegistry;
  private readonly ghRunner: GhCliRunner;
  private readonly allowInsecureLocalForTests: boolean;
  private readonly now: () => number;

  private cachedInstallToken: {
    token: string;
    expiresAtMs: number;
    principalFingerprint: string;
  } | null = null;
  private cachedGhToken: {
    token: string;
    principalFingerprint: string;
  } | null = null;
  private inFlightRefresh: Promise<ResolvedToken> | null = null;

  constructor(opts: {
    auth: GitHubAuthConfig;
    proxy: ProxyState;
    registry?: SecretRegistry;
    ghRunner?: GhCliRunner;
    allowInsecureLocalForTests?: boolean;
    now?: () => number;
  }) {
    this.auth = opts.auth;
    this.proxy = opts.proxy;
    this.registry = opts.registry ?? defaultSecretRegistry;
    this.ghRunner = opts.ghRunner ?? defaultGhCliRunner;
    this.allowInsecureLocalForTests = opts.allowInsecureLocalForTests === true;
    this.now = opts.now ?? (() => Date.now());
  }

  private hasGitHubAppConfig(): boolean {
    return Boolean(
      this.auth.app.appId &&
        this.auth.app.installationId &&
        this.auth.app.privateKeyPem,
    );
  }

  private getAppPrincipalFingerprint(): string {
    const privKey = createPrivateKey(this.auth.app.privateKeyPem!);
    const pubDer = createPublicKey(privKey).export({ type: 'spki', format: 'der' });
    const pubHash = sha256Hex(pubDer);
    return `app:${sha256Hex(`${this.auth.app.appId}\0${this.auth.app.installationId}\0${pubHash}`)}`;
  }

  private deriveGhHostname(): string | undefined {
    if (this.auth.ghHostname) return this.auth.ghHostname;
    try {
      const u = new URL(this.auth.apiBaseUrl);
      const host = u.hostname.toLowerCase();
      if (host === 'api.github.com' || host === 'github.com') return 'github.com';
      return host;
    } catch {
      return undefined;
    }
  }

  async getToken(opts?: { forceRefresh?: boolean; refusedToken?: string }): Promise<ResolvedToken> {
    const mode = this.auth.mode;

    if (mode === 'pat') {
      if (!this.auth.pat) {
        throw new GitHubAuthError('GitHub auth mode is "pat" but no PAT is configured');
      }
      this.registry.register(this.auth.pat);
      return {
        token: this.auth.pat,
        method: 'pat',
        principalFingerprint: `pat:${sha256Hex(this.auth.pat)}`,
      };
    }

    if (mode === 'github_app') {
      if (!this.hasGitHubAppConfig()) {
        throw new GitHubAuthError(
          'GitHub auth mode is "github_app" but appId, installationId, or privateKeyPem is missing',
        );
      }
      return this.getInstallationToken(opts);
    }

    if (mode === 'gh_cli') {
      return this.getGhCliToken(opts);
    }

    // Auto precedence: GitHub App -> PAT -> local gh auth token fallback
    if (this.hasGitHubAppConfig()) {
      return this.getInstallationToken(opts);
    }
    if (this.auth.pat) {
      this.registry.register(this.auth.pat);
      return {
        token: this.auth.pat,
        method: 'pat',
        principalFingerprint: `pat:${sha256Hex(this.auth.pat)}`,
      };
    }
    return this.getGhCliToken(opts);
  }

  private async getGhCliToken(opts?: {
    forceRefresh?: boolean;
    refusedToken?: string;
  }): Promise<ResolvedToken> {
    const hostname = this.deriveGhHostname();
    if (
      !opts?.forceRefresh &&
      this.cachedGhToken &&
      this.cachedGhToken.token !== opts?.refusedToken
    ) {
      return {
        token: this.cachedGhToken.token,
        method: 'gh_cli',
        principalFingerprint: this.cachedGhToken.principalFingerprint,
      };
    }
    const token = await this.ghRunner(hostname);
    this.registry.register(token);
    const principalFingerprint = `gh:${sha256Hex(`${hostname ?? 'github.com'}\0${token}`)}`;
    this.cachedGhToken = { token, principalFingerprint };
    return {
      token,
      method: 'gh_cli',
      principalFingerprint,
    };
  }

  private async getInstallationToken(opts?: {
    forceRefresh?: boolean;
    refusedToken?: string;
  }): Promise<ResolvedToken> {
    const refreshMarginMs = 5 * 60 * 1000; // Refresh 5 minutes before expiry
    if (
      !opts?.forceRefresh &&
      this.cachedInstallToken &&
      this.cachedInstallToken.token !== opts?.refusedToken &&
      this.now() + refreshMarginMs < this.cachedInstallToken.expiresAtMs
    ) {
      return {
        token: this.cachedInstallToken.token,
        method: 'github_app',
        principalFingerprint: this.cachedInstallToken.principalFingerprint,
        expiresAtMs: this.cachedInstallToken.expiresAtMs,
      };
    }

    if (this.inFlightRefresh) {
      return this.inFlightRefresh;
    }

    this.inFlightRefresh = this.fetchInstallationToken().finally(() => {
      this.inFlightRefresh = null;
    });
    return this.inFlightRefresh;
  }

  private async fetchInstallationToken(): Promise<ResolvedToken> {
    const { apiBaseUrl, allowPrivateIntranet } = validateGitHubApiBaseUrl(
      this.auth.apiBaseUrl,
      { allowInsecureLocalForTests: this.allowInsecureLocalForTests },
    );

    const jwt = createGitHubAppJwt(
      this.auth.app.appId,
      this.auth.app.privateKeyPem!,
      Math.floor(this.now() / 1000),
    );
    this.registry.register(jwt);

    const basePath = apiBaseUrl.pathname.replace(/\/+$/, '');
    const tokenUrl = new URL(
      `${apiBaseUrl.origin}${basePath}/app/installations/${encodeURIComponent(this.auth.app.installationId)}/access_tokens`,
    );

    const res = await secureOutboundRequest({
      url: tokenUrl,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'botmux-plugin-github',
      },
      proxy: this.proxy,
      allowPrivateIntranet,
      allowedOrigin: apiBaseUrl.origin,
      skipIpBlockCheck: this.allowInsecureLocalForTests,
      timeoutMs: 15_000,
      maxResponseBytes: 1024 * 1024,
    });

    if (res.status < 200 || res.status >= 300) {
      const msg = this.registry.redactString(res.body.toString('utf8').slice(0, 300));
      throw new GitHubAuthError(
        `GitHub App installation token exchange failed (${res.status}): ${msg}`,
      );
    }

    const parsed = JSON.parse(res.body.toString('utf8')) as {
      token?: string;
      expires_at?: string;
    };
    if (!parsed.token) {
      throw new GitHubAuthError('GitHub App installation token response missing token');
    }

    this.registry.register(parsed.token);
    const expiresAtMs = parsed.expires_at
      ? Date.parse(parsed.expires_at)
      : this.now() + 55 * 60 * 1000;
    const principalFingerprint = this.getAppPrincipalFingerprint();

    this.cachedInstallToken = {
      token: parsed.token,
      expiresAtMs: Number.isNaN(expiresAtMs) ? this.now() + 55 * 60 * 1000 : expiresAtMs,
      principalFingerprint,
    };

    return {
      token: parsed.token,
      method: 'github_app',
      principalFingerprint,
      expiresAtMs: this.cachedInstallToken.expiresAtMs,
    };
  }
}
