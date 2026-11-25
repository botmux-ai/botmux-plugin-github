import { createHash, createPrivateKey } from 'node:crypto';
import type {
  ChatMode,
  GitHubAuthMode,
  PluginConfig,
  PluginConfigPatch,
  RedactedPluginConfig,
  RepoRule,
  SecretPatch,
  TriggerKind,
} from '../types.ts';
import {
  DEFAULT_GITHUB_API_BASE_URL,
  DEFAULT_GROUP_NAME_TEMPLATE,
  DEFAULT_KICKOFF_PROMPT_TEMPLATE,
  DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
  DEFAULT_POLL_INTERVAL_SEC,
  DEFAULT_SERVICE_PORT,
  DEFAULT_WEBHOOK_PATH,
  MIN_POLL_INTERVAL_SEC,
  MIN_WEBHOOK_SECRET_BYTES,
} from '../types.ts';
import {
  formatHostForUrl,
  parseProxyStateFailClosed,
  validateGitHubApiBaseUrl,
} from '../security/net.ts';
import { SecretRegistry, defaultSecretRegistry } from '../security/redact.ts';

export const REPO_SLUG_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$/;
export const LARK_APP_ID_RE = /^cli_[A-Za-z0-9_-]{1,128}$/;
export const GH_HOSTNAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}[A-Za-z0-9])?(?::\d{1,5})?$/;

const MASK_SENTINEL_RE = /^(\*+|•+|\[REDACTED\]|\[TOKEN\]|\[SECRET\]|xxxxx)$/i;

export class ConfigValidationError extends Error {
  readonly code = 'CONFIG_INVALID';
  constructor(message: string) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

export function createDefaultConfig(): PluginConfig {
  return {
    schemaVersion: 1,
    github: {
      mode: 'auto',
      apiBaseUrl: DEFAULT_GITHUB_API_BASE_URL,
      app: {
        appId: '',
        installationId: '',
      },
    },
    proxy: {
      url: '',
    },
    webhook: {
      enabled: false,
      path: DEFAULT_WEBHOOK_PATH,
    },
    service: {
      port: DEFAULT_SERVICE_PORT,
      pollIntervalSec: DEFAULT_POLL_INTERVAL_SEC,
      maxGroupCreatesPerRepoPerHour: DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
    },
    repos: [],
  };
}

export function isWebhookSecretAcceptable(secret: unknown): secret is string {
  if (typeof secret !== 'string') return false;
  const trimmed = secret.trim();
  if (Buffer.byteLength(trimmed, 'utf8') < MIN_WEBHOOK_SECRET_BYTES) return false;
  const distinct = new Set(Array.from(trimmed)).size;
  return distinct >= 8;
}

export function validateRepoSlug(raw: string): string {
  const trimmed = raw.trim();
  if (!REPO_SLUG_RE.test(trimmed)) {
    throw new ConfigValidationError(`Invalid repository slug "${trimmed}" (expected owner/repo)`);
  }
  const [owner, repo] = trimmed.split('/');
  if (owner === '.' || owner === '..' || repo === '.' || repo === '..') {
    throw new ConfigValidationError(`Invalid repository slug "${trimmed}"`);
  }
  return trimmed;
}

export function normalizeRepoKey(repo: string): string {
  return repo.trim().toLowerCase();
}

function normalizeStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

function normalizeTriggerOn(raw: unknown): TriggerKind[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    return ['opened', 'ready_for_review'];
  }
  const out: TriggerKind[] = [];
  for (const item of raw) {
    if (item === 'opened' || item === 'ready_for_review') {
      if (!out.includes(item)) out.push(item);
    }
  }
  return out.length > 0 ? out : ['opened', 'ready_for_review'];
}

function validatePrivateKeyPem(pem: string): void {
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== 'rsa') {
      throw new ConfigValidationError('GitHub App privateKeyPem must be an RSA private key');
    }
    const modulusLength = key.asymmetricKeyDetails?.modulusLength ?? 0;
    if (modulusLength > 0 && modulusLength < 2048) {
      throw new ConfigValidationError('GitHub App RSA private key must be at least 2048 bits');
    }
  } catch (err) {
    if (err instanceof ConfigValidationError) throw err;
    throw new ConfigValidationError('GitHub App privateKeyPem is not a valid PEM private key');
  }
}

export function validateRepoRule(raw: Partial<RepoRule>, index: number): RepoRule {
  if (!raw || typeof raw !== 'object') {
    throw new ConfigValidationError(`Repo rule #${index + 1} must be an object`);
  }
  const repo = validateRepoSlug(String(raw.repo ?? ''));
  const enabled = raw.enabled === true;
  const creatorBotAppId = typeof raw.creatorBotAppId === 'string' ? raw.creatorBotAppId.trim() : '';
  const kickoffBotAppId =
    typeof raw.kickoffBotAppId === 'string' && raw.kickoffBotAppId.trim()
      ? raw.kickoffBotAppId.trim()
      : undefined;
  const memberBotAppIds = normalizeStringArray(raw.memberBotAppIds);

  if (enabled) {
    if (!creatorBotAppId) {
      throw new ConfigValidationError(`Repo "${repo}": creatorBotAppId is required when enabled`);
    }
    if (!LARK_APP_ID_RE.test(creatorBotAppId)) {
      throw new ConfigValidationError(
        `Repo "${repo}": creatorBotAppId "${creatorBotAppId}" must be a valid Lark/Feishu app ID (cli_...)`,
      );
    }
  } else if (creatorBotAppId && !LARK_APP_ID_RE.test(creatorBotAppId)) {
    throw new ConfigValidationError(
      `Repo "${repo}": creatorBotAppId "${creatorBotAppId}" must be a valid Lark/Feishu app ID (cli_...)`,
    );
  }

  for (const m of memberBotAppIds) {
    if (!LARK_APP_ID_RE.test(m)) {
      throw new ConfigValidationError(
        `Repo "${repo}": memberBotAppIds contains invalid app ID "${m}"`,
      );
    }
  }

  if (kickoffBotAppId) {
    if (!LARK_APP_ID_RE.test(kickoffBotAppId)) {
      throw new ConfigValidationError(
        `Repo "${repo}": kickoffBotAppId "${kickoffBotAppId}" must be a valid Lark/Feishu app ID (cli_...)`,
      );
    }
    if (creatorBotAppId && kickoffBotAppId === creatorBotAppId) {
      throw new ConfigValidationError(
        `Repo "${repo}": kickoffBotAppId must be different from creatorBotAppId`,
      );
    }
  }

  const chatMode: ChatMode = raw.chatMode === 'topic' ? 'topic' : 'group';
  const groupNameTemplate =
    typeof raw.groupNameTemplate === 'string' && raw.groupNameTemplate.trim()
      ? raw.groupNameTemplate.trim()
      : DEFAULT_GROUP_NAME_TEMPLATE;
  const kickoffPromptTemplate =
    typeof raw.kickoffPromptTemplate === 'string' && raw.kickoffPromptTemplate.trim()
      ? raw.kickoffPromptTemplate.trim()
      : DEFAULT_KICKOFF_PROMPT_TEMPLATE;

  let bindWorkingDir: string | undefined;
  if (typeof raw.bindWorkingDir === 'string' && raw.bindWorkingDir.trim()) {
    const dir = raw.bindWorkingDir.trim();
    if (dir.includes('\0') || !dir.startsWith('/')) {
      throw new ConfigValidationError(
        `Repo "${repo}": bindWorkingDir must be an absolute path without NUL bytes`,
      );
    }
    bindWorkingDir = dir;
  }

  let pollIntervalSec: number | undefined;
  if (raw.pollIntervalSec !== undefined && raw.pollIntervalSec !== null) {
    const n = Number(raw.pollIntervalSec);
    if (!Number.isInteger(n) || n < MIN_POLL_INTERVAL_SEC || n > 86_400) {
      throw new ConfigValidationError(
        `Repo "${repo}": pollIntervalSec must be an integer between ${MIN_POLL_INTERVAL_SEC} and 86400`,
      );
    }
    pollIntervalSec = n;
  }

  const id =
    typeof raw.id === 'string' && raw.id.trim()
      ? raw.id.trim()
      : normalizeRepoKey(repo);

  return {
    id,
    repo,
    enabled,
    baseBranches: normalizeStringArray(raw.baseBranches),
    triggerOn: normalizeTriggerOn(raw.triggerOn),
    ignoreDrafts: raw.ignoreDrafts !== false,
    authorAllowlist: normalizeStringArray(raw.authorAllowlist),
    authorDenylist: normalizeStringArray(raw.authorDenylist),
    labelAllowlist: normalizeStringArray(raw.labelAllowlist),
    labelDenylist: normalizeStringArray(raw.labelDenylist),
    creatorBotAppId,
    memberBotAppIds,
    ...(kickoffBotAppId ? { kickoffBotAppId } : {}),
    chatMode,
    groupNameTemplate,
    kickoffPromptTemplate,
    ...(bindWorkingDir ? { bindWorkingDir } : {}),
    setTopNotice: raw.setTopNotice !== false,
    postShareLinkToPr: raw.postShareLinkToPr === true,
    onNewCommit: raw.onNewCommit === true,
    onPrClosed: raw.onPrClosed === true,
    ...(pollIntervalSec !== undefined ? { pollIntervalSec } : {}),
  };
}

function normalizeAuthMode(raw: unknown): GitHubAuthMode {
  if (raw === 'pat' || raw === 'github_app' || raw === 'gh_cli' || raw === 'auto') {
    return raw;
  }
  return 'auto';
}

export function normalizeAndValidateConfig(
  raw: unknown,
  opts?: { allowInsecureLocalApiForTests?: boolean },
): PluginConfig {
  const defaults = createDefaultConfig();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return defaults;
  }
  const obj = raw as Record<string, unknown>;
  const rawGh = (obj.github && typeof obj.github === 'object' ? obj.github : {}) as Record<string, unknown>;
  const rawApp = (rawGh.app && typeof rawGh.app === 'object' ? rawGh.app : {}) as Record<string, unknown>;
  const rawProxy = (obj.proxy && typeof obj.proxy === 'object' ? obj.proxy : {}) as Record<string, unknown>;
  const rawWebhook = (obj.webhook && typeof obj.webhook === 'object' ? obj.webhook : {}) as Record<string, unknown>;
  const rawService = (obj.service && typeof obj.service === 'object' ? obj.service : {}) as Record<string, unknown>;

  const apiBaseUrlRaw =
    typeof rawGh.apiBaseUrl === 'string' && rawGh.apiBaseUrl.trim()
      ? rawGh.apiBaseUrl.trim().replace(/\/+$/, '')
      : DEFAULT_GITHUB_API_BASE_URL;
  validateGitHubApiBaseUrl(apiBaseUrlRaw, {
    allowInsecureLocalForTests: opts?.allowInsecureLocalApiForTests,
  });

  const mode = normalizeAuthMode(rawGh.mode);
  const pat = typeof rawGh.pat === 'string' && rawGh.pat.trim() ? rawGh.pat.trim() : undefined;
  const ghHostname =
    typeof rawGh.ghHostname === 'string' && rawGh.ghHostname.trim()
      ? rawGh.ghHostname.trim()
      : undefined;
  if (ghHostname && !GH_HOSTNAME_RE.test(ghHostname)) {
    throw new ConfigValidationError(`Invalid ghHostname: "${ghHostname}"`);
  }

  const appId = typeof rawApp.appId === 'string' ? rawApp.appId.trim() : '';
  const installationId = typeof rawApp.installationId === 'string' ? rawApp.installationId.trim() : '';
  const privateKeyPem =
    typeof rawApp.privateKeyPem === 'string' && rawApp.privateKeyPem.trim()
      ? rawApp.privateKeyPem.trim()
      : undefined;

  if (appId && !/^\d{1,20}$/.test(appId)) {
    throw new ConfigValidationError('github.app.appId must be numeric');
  }
  if (installationId && !/^\d{1,20}$/.test(installationId)) {
    throw new ConfigValidationError('github.app.installationId must be numeric');
  }
  if (privateKeyPem) {
    validatePrivateKeyPem(privateKeyPem);
  }

  const proxyUrl = typeof rawProxy.url === 'string' ? rawProxy.url.trim() : '';
  const proxyUsername =
    typeof rawProxy.username === 'string' && rawProxy.username.trim()
      ? rawProxy.username.trim()
      : undefined;
  const proxyPassword =
    typeof rawProxy.password === 'string' && rawProxy.password.length > 0
      ? rawProxy.password
      : undefined;

  // Fail-closed proxy validation on save/load if non-empty.
  if (proxyUrl) {
    const parsedProxy = parseProxyStateFailClosed(proxyUrl, {
      username: proxyUsername,
      password: proxyPassword,
    });
    if (parsedProxy.kind === 'invalid') {
      throw new ConfigValidationError(parsedProxy.error.message);
    }
  }

  const webhookEnabled = rawWebhook.enabled === true;
  const webhookSecret =
    typeof rawWebhook.secret === 'string' && rawWebhook.secret.trim()
      ? rawWebhook.secret.trim()
      : undefined;
  const webhookPath =
    typeof rawWebhook.path === 'string' && rawWebhook.path.trim().startsWith('/')
      ? rawWebhook.path.trim()
      : DEFAULT_WEBHOOK_PATH;
  if (webhookEnabled && !isWebhookSecretAcceptable(webhookSecret)) {
    throw new ConfigValidationError(
      `Webhook requires a secret of at least ${MIN_WEBHOOK_SECRET_BYTES} UTF-8 bytes with at least 8 distinct characters`,
    );
  }

  const port =
    rawService.port !== undefined ? Number(rawService.port) : DEFAULT_SERVICE_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigValidationError('service.port must be an integer between 1 and 65535');
  }

  const pollIntervalSec =
    rawService.pollIntervalSec !== undefined
      ? Number(rawService.pollIntervalSec)
      : DEFAULT_POLL_INTERVAL_SEC;
  if (!Number.isInteger(pollIntervalSec) || pollIntervalSec < MIN_POLL_INTERVAL_SEC || pollIntervalSec > 86_400) {
    throw new ConfigValidationError(
      `service.pollIntervalSec must be an integer between ${MIN_POLL_INTERVAL_SEC} and 86400`,
    );
  }

  const maxCreates =
    rawService.maxGroupCreatesPerRepoPerHour !== undefined
      ? Number(rawService.maxGroupCreatesPerRepoPerHour)
      : DEFAULT_MAX_GROUP_CREATES_PER_HOUR;
  if (!Number.isInteger(maxCreates) || maxCreates < 1 || maxCreates > 1000) {
    throw new ConfigValidationError(
      'service.maxGroupCreatesPerRepoPerHour must be an integer between 1 and 1000',
    );
  }

  const rawRepos = Array.isArray(obj.repos) ? obj.repos : [];
  const repos: RepoRule[] = [];
  const seenRepoKeys = new Set<string>();
  for (let i = 0; i < rawRepos.length; i++) {
    const rule = validateRepoRule(rawRepos[i] as Partial<RepoRule>, i);
    const key = normalizeRepoKey(rule.repo);
    if (seenRepoKeys.has(key)) {
      throw new ConfigValidationError(`Duplicate repository rule for "${rule.repo}"`);
    }
    seenRepoKeys.add(key);
    repos.push(rule);
  }

  return {
    schemaVersion: 1,
    github: {
      mode,
      apiBaseUrl: apiBaseUrlRaw,
      ...(pat ? { pat } : {}),
      ...(ghHostname ? { ghHostname } : {}),
      app: {
        appId,
        installationId,
        ...(privateKeyPem ? { privateKeyPem } : {}),
      },
    },
    proxy: {
      url: proxyUrl,
      ...(proxyUsername ? { username: proxyUsername } : {}),
      ...(proxyPassword ? { password: proxyPassword } : {}),
    },
    webhook: {
      enabled: webhookEnabled,
      ...(webhookSecret ? { secret: webhookSecret } : {}),
      path: webhookPath,
    },
    service: {
      port,
      pollIntervalSec,
      maxGroupCreatesPerRepoPerHour: maxCreates,
    },
    repos,
  };
}

function stripProxyCredentials(rawUrl: string): { displayUrl: string; hasUrlPassword: boolean } {
  if (!rawUrl || !rawUrl.trim()) return { displayUrl: '', hasUrlPassword: false };
  try {
    const u = new URL(rawUrl.trim());
    const hasUrlPassword = Boolean(u.password);
    const host = formatHostForUrl(u.hostname);
    const portPart = u.port ? `:${u.port}` : '';
    return { displayUrl: `${u.protocol}//${host}${portPart}`, hasUrlPassword };
  } catch {
    return { displayUrl: '', hasUrlPassword: false };
  }
}

/**
 * Produces a strictly browser-safe representation of PluginConfig with ZERO
 * raw tokens, passwords, private keys, or webhook secrets.
 */
export function redactConfig(cfg: PluginConfig): RedactedPluginConfig {
  const { displayUrl, hasUrlPassword } = stripProxyCredentials(cfg.proxy.url);
  return {
    schemaVersion: 1,
    github: {
      mode: cfg.github.mode,
      apiBaseUrl: cfg.github.apiBaseUrl,
      hasPat: Boolean(cfg.github.pat),
      ...(cfg.github.ghHostname ? { ghHostname: cfg.github.ghHostname } : {}),
      app: {
        appId: cfg.github.app.appId,
        installationId: cfg.github.app.installationId,
        hasPrivateKey: Boolean(cfg.github.app.privateKeyPem),
      },
    },
    proxy: {
      url: displayUrl,
      ...(cfg.proxy.username ? { username: cfg.proxy.username } : {}),
      hasPassword: Boolean(cfg.proxy.password) || hasUrlPassword,
    },
    webhook: {
      enabled: cfg.webhook.enabled,
      hasSecret: Boolean(cfg.webhook.secret),
      path: cfg.webhook.path ?? DEFAULT_WEBHOOK_PATH,
    },
    service: { ...cfg.service },
    repos: cfg.repos.map(r => ({
      ...r,
      baseBranches: [...r.baseBranches],
      triggerOn: [...r.triggerOn],
      authorAllowlist: [...r.authorAllowlist],
      authorDenylist: [...r.authorDenylist],
      labelAllowlist: [...r.labelAllowlist],
      labelDenylist: [...r.labelDenylist],
      memberBotAppIds: [...r.memberBotAppIds],
    })),
  };
}

function resolveSecretPatch(
  existing: string | undefined,
  incoming: string | SecretPatch | undefined,
  clearFlag: boolean | undefined,
  fieldName: string,
): string | undefined {
  if (clearFlag === true) return undefined;
  if (incoming === undefined || incoming === null) return existing;
  if (typeof incoming === 'object') {
    if (incoming.action === 'clear') return undefined;
    if (incoming.action === 'keep') return existing;
    if (incoming.action === 'set') {
      const val = typeof incoming.value === 'string' ? incoming.value.trim() : '';
      if (!val) return existing;
      if (MASK_SENTINEL_RE.test(val)) {
        throw new ConfigValidationError(`Refused masked placeholder for ${fieldName}`);
      }
      return val;
    }
    return existing;
  }
  const trimmed = incoming.trim();
  if (!trimmed) return existing;
  if (MASK_SENTINEL_RE.test(trimmed)) {
    throw new ConfigValidationError(`Refused masked placeholder for ${fieldName}`);
  }
  return trimmed;
}

function normalizedOriginKey(rawUrl: string): string {
  if (!rawUrl || !rawUrl.trim()) return '';
  try {
    const u = new URL(rawUrl.trim());
    const port = u.port || (u.protocol === 'https:' ? '443' : '80');
    return `${u.protocol}//${u.hostname.toLowerCase()}:${port}`;
  } catch {
    return rawUrl.trim();
  }
}

export function apiOriginChanged(currentApiBaseUrl: string, nextApiBaseUrl: string | undefined): boolean {
  if (!nextApiBaseUrl || !nextApiBaseUrl.trim()) return false;
  return normalizedOriginKey(currentApiBaseUrl) !== normalizedOriginKey(nextApiBaseUrl);
}

/**
 * Merges a partial write-only settings patch into an existing PluginConfig:
 * - Preserves stored secrets when omitted or empty
 * - Rejects masked placeholders (e.g. "***", "[REDACTED]")
 * - Clears secrets on explicit clear flag or { action: 'clear' }
 * - Automatically drops stored GitHub PAT & App privateKeyPem if github.apiBaseUrl origin changes
 * - Automatically drops stored proxy credentials if proxy scheme/host/port changes
 */
export function applyConfigPatch(
  current: PluginConfig,
  patch: PluginConfigPatch,
  opts?: { allowInsecureLocalApiForTests?: boolean },
): PluginConfig {
  const nextApiBaseUrl = patch.github?.apiBaseUrl ?? current.github.apiBaseUrl;
  const ghOriginChanged = apiOriginChanged(current.github.apiBaseUrl, patch.github?.apiBaseUrl);

  const nextPat = resolveSecretPatch(
    ghOriginChanged ? undefined : current.github.pat,
    patch.github?.pat,
    patch.github?.clearPat,
    'github.pat',
  );
  const nextPrivateKey = resolveSecretPatch(
    ghOriginChanged ? undefined : current.github.app.privateKeyPem,
    patch.github?.app?.privateKeyPem,
    patch.github?.app?.clearPrivateKey,
    'github.app.privateKeyPem',
  );
  const nextWebhookSecret = resolveSecretPatch(
    current.webhook.secret,
    patch.webhook?.secret,
    patch.webhook?.clearSecret,
    'webhook.secret',
  );

  // Validate incoming proxy.url fail-closed BEFORE stripping embedded credentials!
  const nextProxyUrlRaw =
    patch.proxy?.url !== undefined ? patch.proxy.url.trim() : current.proxy.url;
  const proxyTargetChanged =
    normalizedOriginKey(nextProxyUrlRaw) !== normalizedOriginKey(current.proxy.url);

  let nextProxyUrl = nextProxyUrlRaw;
  let embeddedUser: string | undefined;
  let embeddedPass: string | undefined;
  if (nextProxyUrlRaw) {
    const precheck = parseProxyStateFailClosed(nextProxyUrlRaw);
    if (precheck.kind === 'invalid') {
      throw new ConfigValidationError(precheck.error.message);
    }
    const parsed = new URL(nextProxyUrlRaw);
    if (parsed.username) embeddedUser = decodeURIComponent(parsed.username);
    if (parsed.password) {
      const dec = decodeURIComponent(parsed.password);
      if (MASK_SENTINEL_RE.test(dec.trim())) {
        throw new ConfigValidationError('Refused masked placeholder for proxy.password');
      }
      embeddedPass = dec;
    }
    // Strip embedded credentials from stored proxy.url; keep creds in username/password fields.
    if (parsed.username || parsed.password) {
      const host = formatHostForUrl(parsed.hostname);
      const portPart = parsed.port ? `:${parsed.port}` : '';
      nextProxyUrl = `${parsed.protocol}//${host}${portPart}`;
    }
  }

  const basePasswordForMerge = proxyTargetChanged ? undefined : current.proxy.password;
  const nextProxyPassword = embeddedPass
    ? embeddedPass
    : resolveSecretPatch(
        basePasswordForMerge,
        patch.proxy?.password,
        patch.proxy?.clearPassword,
        'proxy.password',
      );
  const nextProxyUsername =
    embeddedUser !== undefined
      ? embeddedUser
      : patch.proxy?.username !== undefined
        ? patch.proxy.username.trim() || undefined
        : proxyTargetChanged
          ? undefined
          : current.proxy.username;

  const merged = {
    schemaVersion: 1 as const,
    github: {
      mode: patch.github?.mode ?? current.github.mode,
      apiBaseUrl: nextApiBaseUrl,
      ...(nextPat ? { pat: nextPat } : {}),
      ...(patch.github?.ghHostname !== undefined
        ? patch.github.ghHostname.trim()
          ? { ghHostname: patch.github.ghHostname.trim() }
          : {}
        : current.github.ghHostname
          ? { ghHostname: current.github.ghHostname }
          : {}),
      app: {
        appId: patch.github?.app?.appId ?? current.github.app.appId,
        installationId:
          patch.github?.app?.installationId ?? current.github.app.installationId,
        ...(nextPrivateKey ? { privateKeyPem: nextPrivateKey } : {}),
      },
    },
    proxy: {
      url: nextProxyUrl,
      ...(nextProxyUrl && nextProxyUsername ? { username: nextProxyUsername } : {}),
      ...(nextProxyUrl && nextProxyPassword ? { password: nextProxyPassword } : {}),
    },
    webhook: {
      enabled: patch.webhook?.enabled ?? current.webhook.enabled,
      ...(nextWebhookSecret ? { secret: nextWebhookSecret } : {}),
      path: patch.webhook?.path ?? current.webhook.path ?? DEFAULT_WEBHOOK_PATH,
    },
    service: {
      port: patch.service?.port ?? current.service.port,
      pollIntervalSec: patch.service?.pollIntervalSec ?? current.service.pollIntervalSec,
      maxGroupCreatesPerRepoPerHour:
        patch.service?.maxGroupCreatesPerRepoPerHour ??
        current.service.maxGroupCreatesPerRepoPerHour,
    },
    repos: patch.repos !== undefined ? patch.repos : current.repos,
  };

  return normalizeAndValidateConfig(merged, opts);
}

export function registerConfigSecrets(
  cfg: PluginConfig,
  registry: SecretRegistry = defaultSecretRegistry,
): void {
  registry.register(cfg.github.pat);
  registry.register(cfg.github.app.privateKeyPem);
  registry.register(cfg.webhook.secret);
  registry.registerBasicPair(cfg.proxy.username, cfg.proxy.password);
  if (cfg.proxy.url) {
    try {
      const parsed = new URL(cfg.proxy.url);
      if (parsed.password) {
        registry.registerBasicPair(
          parsed.username ? decodeURIComponent(parsed.username) : '',
          decodeURIComponent(parsed.password),
        );
      }
    } catch {
      // Ignore malformed raw proxy URL during registration
    }
  }
}

export function computeRuleFilterHash(rule: RepoRule): string {
  const payload = JSON.stringify({
    enabled: rule.enabled,
    baseBranches: [...rule.baseBranches].sort(),
    triggerOn: [...rule.triggerOn].sort(),
    ignoreDrafts: rule.ignoreDrafts,
    authorAllowlist: [...rule.authorAllowlist].map(s => s.toLowerCase()).sort(),
    authorDenylist: [...rule.authorDenylist].map(s => s.toLowerCase()).sort(),
    labelAllowlist: [...rule.labelAllowlist].map(s => s.toLowerCase()).sort(),
    labelDenylist: [...rule.labelDenylist].map(s => s.toLowerCase()).sort(),
    onNewCommit: rule.onNewCommit,
    onPrClosed: rule.onPrClosed,
  });
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}
