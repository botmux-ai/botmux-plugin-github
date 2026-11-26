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

function assertOptionalStringArray(raw: unknown, fieldName: string): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new ConfigValidationError(`Config field "${fieldName}" must be an array of strings`);
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i];
    if (typeof item !== 'string') {
      throw new ConfigValidationError(
        `Config field "${fieldName}[${i}]" must be a string`,
      );
    }
    const trimmed = item.trim();
    if (!trimmed) continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      out.push(trimmed);
    }
  }
  return out;
}

function assertOptionalBoolean(raw: unknown, fieldName: string, defaultValue: boolean): boolean {
  if (raw === undefined) return defaultValue;
  if (typeof raw !== 'boolean') {
    throw new ConfigValidationError(`Config field "${fieldName}" must be a boolean`);
  }
  return raw;
}

function assertOptionalTriggerOn(raw: unknown, fieldName: string): TriggerKind[] {
  if (raw === undefined) {
    return ['opened', 'ready_for_review'];
  }
  if (!Array.isArray(raw)) {
    throw new ConfigValidationError(
      `Config field "${fieldName}" must be an array of "opened" | "ready_for_review"`,
    );
  }
  if (raw.length === 0) {
    throw new ConfigValidationError(`Config field "${fieldName}" must not be empty`);
  }
  const out: TriggerKind[] = [];
  for (let i = 0; i < raw.length; i++) {
    const item = raw[i];
    if (item !== 'opened' && item !== 'ready_for_review') {
      throw new ConfigValidationError(
        `Config field "${fieldName}[${i}]" must be "opened" or "ready_for_review"`,
      );
    }
    if (!out.includes(item)) out.push(item);
  }
  return out;
}

function assertOptionalChatMode(raw: unknown, fieldName: string): ChatMode {
  if (raw === undefined) return 'group';
  if (raw !== 'group' && raw !== 'topic') {
    throw new ConfigValidationError(`Config field "${fieldName}" must be "group" or "topic"`);
  }
  return raw;
}

function assertOptionalIntField(
  raw: unknown,
  fieldName: string,
  min: number,
  max: number,
  defaultValue: number,
): number {
  if (raw === undefined) return defaultValue;
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < min || raw > max) {
    throw new ConfigValidationError(
      `Config field "${fieldName}" must be an integer between ${min} and ${max}`,
    );
  }
  return raw;
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
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigValidationError(`Repo rule #${index + 1} must be an object`);
  }
  const prefix = `repos[${index}]`;
  if (typeof raw.repo !== 'string') {
    throw new ConfigValidationError(`Config field "${prefix}.repo" must be a string`);
  }
  const repo = validateRepoSlug(raw.repo);
  const enabled = assertOptionalBoolean(raw.enabled, `${prefix}.enabled`, false);

  const creatorField = assertOptionalStringField(raw.creatorBotAppId, `${prefix}.creatorBotAppId`);
  const creatorBotAppId = creatorField ? creatorField.trim() : '';

  const kickoffField = assertOptionalStringField(raw.kickoffBotAppId, `${prefix}.kickoffBotAppId`);
  const kickoffBotAppId = kickoffField && kickoffField.trim() ? kickoffField.trim() : undefined;

  const memberBotAppIds = assertOptionalStringArray(
    raw.memberBotAppIds,
    `${prefix}.memberBotAppIds`,
  );

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

  const chatMode = assertOptionalChatMode(raw.chatMode, `${prefix}.chatMode`);
  const groupTplField = assertOptionalStringField(
    raw.groupNameTemplate,
    `${prefix}.groupNameTemplate`,
  );
  const groupNameTemplate =
    groupTplField && groupTplField.trim() ? groupTplField.trim() : DEFAULT_GROUP_NAME_TEMPLATE;

  const kickoffTplField = assertOptionalStringField(
    raw.kickoffPromptTemplate,
    `${prefix}.kickoffPromptTemplate`,
  );
  const kickoffPromptTemplate =
    kickoffTplField && kickoffTplField.trim()
      ? kickoffTplField.trim()
      : DEFAULT_KICKOFF_PROMPT_TEMPLATE;

  const bindDirField = assertOptionalStringField(raw.bindWorkingDir, `${prefix}.bindWorkingDir`);
  let bindWorkingDir: string | undefined;
  if (bindDirField && bindDirField.trim()) {
    const dir = bindDirField.trim();
    if (dir.includes('\0') || !dir.startsWith('/')) {
      throw new ConfigValidationError(
        `Repo "${repo}": bindWorkingDir must be an absolute path without NUL bytes`,
      );
    }
    bindWorkingDir = dir;
  }

  let pollIntervalSec: number | undefined;
  if (raw.pollIntervalSec !== undefined) {
    if (
      typeof raw.pollIntervalSec !== 'number' ||
      !Number.isInteger(raw.pollIntervalSec) ||
      raw.pollIntervalSec < MIN_POLL_INTERVAL_SEC ||
      raw.pollIntervalSec > 86_400
    ) {
      throw new ConfigValidationError(
        `Repo "${repo}": pollIntervalSec must be an integer between ${MIN_POLL_INTERVAL_SEC} and 86400`,
      );
    }
    pollIntervalSec = raw.pollIntervalSec;
  }

  const idField = assertOptionalStringField(raw.id, `${prefix}.id`);
  const id = idField && idField.trim() ? idField.trim() : normalizeRepoKey(repo);

  return {
    id,
    repo,
    enabled,
    baseBranches: assertOptionalStringArray(raw.baseBranches, `${prefix}.baseBranches`),
    triggerOn: assertOptionalTriggerOn(raw.triggerOn, `${prefix}.triggerOn`),
    ignoreDrafts: assertOptionalBoolean(raw.ignoreDrafts, `${prefix}.ignoreDrafts`, true),
    authorAllowlist: assertOptionalStringArray(raw.authorAllowlist, `${prefix}.authorAllowlist`),
    authorDenylist: assertOptionalStringArray(raw.authorDenylist, `${prefix}.authorDenylist`),
    labelAllowlist: assertOptionalStringArray(raw.labelAllowlist, `${prefix}.labelAllowlist`),
    labelDenylist: assertOptionalStringArray(raw.labelDenylist, `${prefix}.labelDenylist`),
    creatorBotAppId,
    memberBotAppIds,
    ...(kickoffBotAppId ? { kickoffBotAppId } : {}),
    chatMode,
    groupNameTemplate,
    kickoffPromptTemplate,
    ...(bindWorkingDir ? { bindWorkingDir } : {}),
    setTopNotice: assertOptionalBoolean(raw.setTopNotice, `${prefix}.setTopNotice`, true),
    postShareLinkToPr: assertOptionalBoolean(
      raw.postShareLinkToPr,
      `${prefix}.postShareLinkToPr`,
      false,
    ),
    onNewCommit: assertOptionalBoolean(raw.onNewCommit, `${prefix}.onNewCommit`, false),
    onPrClosed: assertOptionalBoolean(raw.onPrClosed, `${prefix}.onPrClosed`, false),
    ...(pollIntervalSec !== undefined ? { pollIntervalSec } : {}),
  };
}

function assertOptionalPlainObject(
  val: unknown,
  fieldName: string,
): Record<string, unknown> {
  if (val === undefined) return {};
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    throw new ConfigValidationError(`Config field "${fieldName}" must be a JSON object`);
  }
  return val as Record<string, unknown>;
}

function assertOptionalStringField(val: unknown, fieldName: string): string | undefined {
  if (val === undefined) return undefined;
  if (typeof val !== 'string') {
    throw new ConfigValidationError(`Config field "${fieldName}" must be a string`);
  }
  return val;
}

function normalizeAuthMode(raw: unknown): GitHubAuthMode {
  if (raw === undefined) return 'auto';
  if (raw === 'pat' || raw === 'github_app' || raw === 'gh_cli' || raw === 'auto') {
    return raw;
  }
  throw new ConfigValidationError(`Invalid github.mode: "${String(raw)}"`);
}

export function normalizeAndValidateConfig(
  raw: unknown,
  opts?: { allowInsecureLocalApiForTests?: boolean },
): PluginConfig {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigValidationError('Configuration root must be a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schemaVersion !== undefined && obj.schemaVersion !== 1) {
    throw new ConfigValidationError(`Unsupported config schemaVersion: ${String(obj.schemaVersion)}`);
  }
  const rawGh = assertOptionalPlainObject(obj.github, 'github');
  const rawApp = assertOptionalPlainObject(rawGh.app, 'github.app');
  const rawProxy = assertOptionalPlainObject(obj.proxy, 'proxy');
  const rawWebhook = assertOptionalPlainObject(obj.webhook, 'webhook');
  const rawService = assertOptionalPlainObject(obj.service, 'service');

  const apiBaseUrlField = assertOptionalStringField(rawGh.apiBaseUrl, 'github.apiBaseUrl');
  const apiBaseUrlRaw =
    apiBaseUrlField && apiBaseUrlField.trim()
      ? apiBaseUrlField.trim().replace(/\/+$/, '')
      : DEFAULT_GITHUB_API_BASE_URL;
  validateGitHubApiBaseUrl(apiBaseUrlRaw, {
    allowInsecureLocalForTests: opts?.allowInsecureLocalApiForTests,
  });

  const mode = normalizeAuthMode(rawGh.mode);
  const patField = assertOptionalStringField(rawGh.pat, 'github.pat');
  const pat = patField && patField.trim() ? patField.trim() : undefined;
  const ghHostnameField = assertOptionalStringField(rawGh.ghHostname, 'github.ghHostname');
  const ghHostname =
    ghHostnameField && ghHostnameField.trim() ? ghHostnameField.trim() : undefined;
  if (ghHostname && !GH_HOSTNAME_RE.test(ghHostname)) {
    throw new ConfigValidationError(`Invalid ghHostname: "${ghHostname}"`);
  }

  const appId = (assertOptionalStringField(rawApp.appId, 'github.app.appId') ?? '').trim();
  const installationId = (
    assertOptionalStringField(rawApp.installationId, 'github.app.installationId') ?? ''
  ).trim();
  const pemField = assertOptionalStringField(rawApp.privateKeyPem, 'github.app.privateKeyPem');
  const privateKeyPem = pemField && pemField.trim() ? pemField.trim() : undefined;

  if (appId && !/^\d{1,20}$/.test(appId)) {
    throw new ConfigValidationError('github.app.appId must be numeric');
  }
  if (installationId && !/^\d{1,20}$/.test(installationId)) {
    throw new ConfigValidationError('github.app.installationId must be numeric');
  }
  if (privateKeyPem) {
    validatePrivateKeyPem(privateKeyPem);
  }

  const proxyUrl = (assertOptionalStringField(rawProxy.url, 'proxy.url') ?? '').trim();
  const proxyUserField = assertOptionalStringField(rawProxy.username, 'proxy.username');
  const proxyUsername =
    proxyUserField && proxyUserField.trim() ? proxyUserField.trim() : undefined;
  const proxyPassField = assertOptionalStringField(rawProxy.password, 'proxy.password');
  const proxyPassword = proxyPassField && proxyPassField.length > 0 ? proxyPassField : undefined;

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

  if (rawWebhook.enabled !== undefined && typeof rawWebhook.enabled !== 'boolean') {
    throw new ConfigValidationError('Config field "webhook.enabled" must be a boolean');
  }
  const webhookEnabled = rawWebhook.enabled === true;
  const whSecretField = assertOptionalStringField(rawWebhook.secret, 'webhook.secret');
  const webhookSecret =
    whSecretField && whSecretField.trim() ? whSecretField.trim() : undefined;
  const whPathField = assertOptionalStringField(rawWebhook.path, 'webhook.path');
  let webhookPath = DEFAULT_WEBHOOK_PATH;
  if (whPathField !== undefined && whPathField.trim()) {
    const trimmedPath = whPathField.trim();
    if (!trimmedPath.startsWith('/')) {
      throw new ConfigValidationError('Config field "webhook.path" must start with "/"');
    }
    webhookPath = trimmedPath;
  }
  if (webhookEnabled && !isWebhookSecretAcceptable(webhookSecret)) {
    throw new ConfigValidationError(
      `Webhook requires a secret of at least ${MIN_WEBHOOK_SECRET_BYTES} UTF-8 bytes with at least 8 distinct characters`,
    );
  }

  const port = assertOptionalIntField(rawService.port, 'service.port', 1, 65535, DEFAULT_SERVICE_PORT);
  const pollIntervalSec = assertOptionalIntField(
    rawService.pollIntervalSec,
    'service.pollIntervalSec',
    MIN_POLL_INTERVAL_SEC,
    86_400,
    DEFAULT_POLL_INTERVAL_SEC,
  );
  const maxCreates = assertOptionalIntField(
    rawService.maxGroupCreatesPerRepoPerHour,
    'service.maxGroupCreatesPerRepoPerHour',
    1,
    1000,
    DEFAULT_MAX_GROUP_CREATES_PER_HOUR,
  );

  if (obj.repos !== undefined && !Array.isArray(obj.repos)) {
    throw new ConfigValidationError('Config field "repos" must be an array');
  }
  const rawRepos = obj.repos ?? [];
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

function extractProxyUrlUserinfo(rawUrl: string): {
  displayUrl: string;
  username?: string;
  password?: string;
} {
  if (!rawUrl || !rawUrl.trim()) return { displayUrl: '' };
  try {
    const u = new URL(rawUrl.trim());
    const host = formatHostForUrl(u.hostname);
    const portPart = u.port ? `:${u.port}` : '';
    const displayUrl = `${u.protocol}//${host}${portPart}`;
    let username: string | undefined;
    let password: string | undefined;
    try {
      if (u.username) username = decodeURIComponent(u.username);
      if (u.password) password = decodeURIComponent(u.password);
    } catch {
      // Ignore malformed percent-escape in fallback extraction
    }
    return {
      displayUrl,
      ...(username ? { username } : {}),
      ...(password ? { password } : {}),
    };
  } catch {
    return { displayUrl: '' };
  }
}

/**
 * Produces a strictly browser-safe representation of PluginConfig with ZERO
 * raw tokens, passwords, private keys, or webhook secrets.
 */
export function redactConfig(cfg: PluginConfig): RedactedPluginConfig {
  const urlInfo = extractProxyUrlUserinfo(cfg.proxy.url);
  const effectiveUsername = cfg.proxy.username || urlInfo.username;
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
      url: urlInfo.displayUrl,
      ...(effectiveUsername ? { username: effectiveUsername } : {}),
      hasPassword: Boolean(cfg.proxy.password) || Boolean(urlInfo.password),
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
  incoming: unknown,
  clearFlag: unknown,
  fieldName: string,
): string | undefined {
  const clear = assertOptionalBoolean(clearFlag, `${fieldName} clear flag`, false);
  if (clear) return undefined;
  if (incoming === undefined) return existing;
  if (incoming === null) {
    throw new ConfigValidationError(`Config field "${fieldName}" must be a string or secret patch object`);
  }
  if (typeof incoming === 'object') {
    if (Array.isArray(incoming)) {
      throw new ConfigValidationError(`Config field "${fieldName}" must not be an array`);
    }
    const obj = incoming as Record<string, unknown>;
    if (obj.action === 'clear') return undefined;
    if (obj.action === 'keep') return existing;
    if (obj.action === 'set') {
      if (typeof obj.value !== 'string') {
        throw new ConfigValidationError(`Config field "${fieldName}.value" must be a string`);
      }
      const val = obj.value.trim();
      if (!val) return existing;
      if (MASK_SENTINEL_RE.test(val)) {
        throw new ConfigValidationError(`Refused masked placeholder for ${fieldName}`);
      }
      return val;
    }
    throw new ConfigValidationError(`Invalid secret patch action for "${fieldName}"`);
  }
  if (typeof incoming !== 'string') {
    throw new ConfigValidationError(`Config field "${fieldName}" must be a string`);
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
 * - Strictly rejects wrong-typed or null patch sections/fields (never silently coerces!)
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
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    throw new ConfigValidationError('Config patch must be a JSON object');
  }
  const pObj = patch as Record<string, unknown>;
  if (pObj.schemaVersion !== undefined && pObj.schemaVersion !== 1) {
    throw new ConfigValidationError(`Unsupported config schemaVersion: ${String(pObj.schemaVersion)}`);
  }

  const pGh = assertOptionalPlainObject(pObj.github, 'github');
  const pApp = assertOptionalPlainObject(pGh.app, 'github.app');
  const pProxy = assertOptionalPlainObject(pObj.proxy, 'proxy');
  const pWebhook = assertOptionalPlainObject(pObj.webhook, 'webhook');
  const pService = assertOptionalPlainObject(pObj.service, 'service');

  const patchApiBaseUrl = assertOptionalStringField(pGh.apiBaseUrl, 'github.apiBaseUrl');
  const nextApiBaseUrl = patchApiBaseUrl !== undefined ? patchApiBaseUrl : current.github.apiBaseUrl;
  const ghOriginChanged = apiOriginChanged(current.github.apiBaseUrl, patchApiBaseUrl);

  const nextPat = resolveSecretPatch(
    ghOriginChanged ? undefined : current.github.pat,
    pGh.pat,
    pGh.clearPat,
    'github.pat',
  );
  const nextPrivateKey = resolveSecretPatch(
    ghOriginChanged ? undefined : current.github.app.privateKeyPem,
    pApp.privateKeyPem,
    pApp.clearPrivateKey,
    'github.app.privateKeyPem',
  );
  const nextWebhookSecret = resolveSecretPatch(
    current.webhook.secret,
    pWebhook.secret,
    pWebhook.clearSecret,
    'webhook.secret',
  );

  // Validate incoming proxy.url fail-closed BEFORE stripping embedded credentials!
  const patchProxyUrl = assertOptionalStringField(pProxy.url, 'proxy.url');
  const urlProvidedInPatch = patchProxyUrl !== undefined;
  const nextProxyUrlRaw = urlProvidedInPatch ? patchProxyUrl.trim() : current.proxy.url;
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
    if (urlProvidedInPatch) {
      if (parsed.username) embeddedUser = decodeURIComponent(parsed.username);
      if (parsed.password) {
        const dec = decodeURIComponent(parsed.password);
        if (MASK_SENTINEL_RE.test(dec.trim())) {
          throw new ConfigValidationError('Refused masked placeholder for proxy.password');
        }
        embeddedPass = dec;
      }
    }
    if (parsed.username || parsed.password) {
      const host = formatHostForUrl(parsed.hostname);
      const portPart = parsed.port ? `:${parsed.port}` : '';
      nextProxyUrl = `${parsed.protocol}//${host}${portPart}`;
    }
  }

  const currentUrlInfo = extractProxyUrlUserinfo(current.proxy.url);
  const existingProxyUsername = current.proxy.username || currentUrlInfo.username;
  const existingProxyPassword = current.proxy.password || currentUrlInfo.password;

  const basePasswordForMerge = proxyTargetChanged ? undefined : existingProxyPassword;
  const nextProxyPassword = embeddedPass
    ? embeddedPass
    : resolveSecretPatch(
        basePasswordForMerge,
        pProxy.password,
        pProxy.clearPassword,
        'proxy.password',
      );
  const patchProxyUsername = assertOptionalStringField(pProxy.username, 'proxy.username');
  const explicitUsername = patchProxyUsername !== undefined ? patchProxyUsername.trim() : undefined;
  const nextProxyUsername =
    embeddedUser !== undefined
      ? embeddedUser
      : proxyTargetChanged
        ? explicitUsername || undefined
        : explicitUsername
          ? explicitUsername
          : patchProxyUsername === '' && current.proxy.username !== undefined
            ? undefined
            : existingProxyUsername;

  const patchGhHostname = assertOptionalStringField(pGh.ghHostname, 'github.ghHostname');

  // Use explicit `!== undefined` (NOT `??`) so explicit `null` values propagate and fail closed!
  const merged = {
    schemaVersion: 1 as const,
    github: {
      mode: pGh.mode !== undefined ? pGh.mode : current.github.mode,
      apiBaseUrl: nextApiBaseUrl,
      ...(nextPat ? { pat: nextPat } : {}),
      ...(patchGhHostname !== undefined
        ? patchGhHostname.trim()
          ? { ghHostname: patchGhHostname.trim() }
          : {}
        : current.github.ghHostname
          ? { ghHostname: current.github.ghHostname }
          : {}),
      app: {
        appId: pApp.appId !== undefined ? pApp.appId : current.github.app.appId,
        installationId:
          pApp.installationId !== undefined
            ? pApp.installationId
            : current.github.app.installationId,
        ...(nextPrivateKey ? { privateKeyPem: nextPrivateKey } : {}),
      },
    },
    proxy: {
      url: nextProxyUrl,
      ...(nextProxyUrl && nextProxyUsername ? { username: nextProxyUsername } : {}),
      ...(nextProxyUrl && nextProxyPassword ? { password: nextProxyPassword } : {}),
    },
    webhook: {
      enabled: pWebhook.enabled !== undefined ? pWebhook.enabled : current.webhook.enabled,
      ...(nextWebhookSecret ? { secret: nextWebhookSecret } : {}),
      path:
        pWebhook.path !== undefined
          ? pWebhook.path
          : (current.webhook.path ?? DEFAULT_WEBHOOK_PATH),
    },
    service: {
      port: pService.port !== undefined ? pService.port : current.service.port,
      pollIntervalSec:
        pService.pollIntervalSec !== undefined
          ? pService.pollIntervalSec
          : current.service.pollIntervalSec,
      maxGroupCreatesPerRepoPerHour:
        pService.maxGroupCreatesPerRepoPerHour !== undefined
          ? pService.maxGroupCreatesPerRepoPerHour
          : current.service.maxGroupCreatesPerRepoPerHour,
    },
    repos: pObj.repos !== undefined ? pObj.repos : current.repos,
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
