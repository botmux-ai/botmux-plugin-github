import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import type {
  LarkBrand,
  PrGroupRecord,
  ProxyConfig,
  PullRequestInfo,
  RepoRule,
} from '../types.ts';
import { MAX_IPC_TEXT_BYTES } from '../types.ts';
import { acquireSecureLock } from '../security/fs.ts';
import { loopbackRequest } from '../security/net.ts';
import { SecretRegistry, defaultSecretRegistry, formatSafeError } from '../security/redact.ts';
import {
  buildKickoffPrompt,
  makeCanonicalPrGroupPrefix,
  renderSafeGroupName,
} from '../security/sanitize.ts';
import type { StateStore } from '../state/store.ts';
import { makePrKey } from '../state/store.ts';
import type { GitHubClient } from '../github/client.ts';
import {
  discoverOnlineDaemons,
  loadBotsConfig,
  loadBotsInfo,
  loadCreatorScopedBotOpenIds,
  loadDashboardSecret,
  resolveBotmuxBin,
  signDaemonIpcHeaders,
  type DiscoveryOptions,
} from './discovery.ts';
import { LarkOpenApiClient, normalizeTrustedLarkShareLink } from './lark.ts';

const CHAT_ID_RE = /^oc_[A-Za-z0-9_-]{1,128}$/;
const MESSAGE_ID_RE = /^om_[A-Za-z0-9_-]{1,128}$/;
const OPEN_ID_RE = /^ou_[A-Za-z0-9_-]{1,128}$/;
export const DEFAULT_UNKNOWN_OUTCOME_SETTLE_MS = 120_000;

export interface CliExecFn {
  (
    bin: string,
    args: string[],
    opts: { timeoutMs: number; env: Record<string, string | undefined> },
  ): Promise<{
    exitCode: number;
    stdout: string;
    stderr: string;
    errorCode?: string;
    killed?: boolean;
    signal?: string | null;
  }>;
}

export interface HostBridgeOptions {
  stateStore: StateStore;
  discovery?: DiscoveryOptions;
  proxy?: ProxyConfig;
  registry?: SecretRegistry;
  larkClient?: LarkOpenApiClient;
  cliExec?: CliExecFn;
  unknownOutcomeSettleMs?: number;
  now?: () => number;
}

export interface GroupOrchestrationResult {
  record: PrGroupRecord;
  reusedExisting: boolean;
  warnings: string[];
}

interface DaemonGroupItem {
  chatId: string;
  name?: string;
  description?: string;
  chatStatus?: string;
}

interface DaemonCreateGroupResponse {
  ok?: boolean;
  chatId?: string;
  shareLink?: string | null;
  kickoffMessageId?: string | null;
  kickoffError?: string | null;
  error?: string;
}

interface DaemonReadMessageResponse {
  ok?: boolean;
  messageId?: string;
  chatId?: string;
  deleted?: boolean;
  text?: string | null;
}

function defaultCliExec(
  bin: string,
  args: string[],
  opts: { timeoutMs: number; env: Record<string, string | undefined> },
): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
  errorCode?: string;
  killed?: boolean;
  signal?: string | null;
}> {
  return new Promise(resolvePromise => {
    execFile(
      bin,
      args,
      {
        shell: false,
        timeout: opts.timeoutMs,
        maxBuffer: 256 * 1024,
        env: opts.env,
      },
      (err, stdout, stderr) => {
        const rawCode = err ? (err as { code?: unknown }).code : undefined;
        const exitCode = typeof rawCode === 'number' ? rawCode : err ? 1 : 0;
        const errorCode = typeof rawCode === 'string' ? rawCode : undefined;
        const killed = Boolean(err && (err as { killed?: boolean }).killed);
        const signal = err ? ((err as { signal?: string | null }).signal ?? null) : null;
        resolvePromise({
          exitCode,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          ...(errorCode ? { errorCode } : {}),
          ...(killed ? { killed } : {}),
          ...(signal ? { signal } : {}),
        });
      },
    );
  });
}

class CliPreCreateError extends Error {
  readonly definitelyNotCreated = true;
  constructor(message: string) {
    super(message);
    this.name = 'CliPreCreateError';
  }
}

// Strictly line-anchored CLI pre-create validation errors (prevents false-matching post-create errors or echoed PR text)
const DEFINITE_CLI_PRECREATE_ERR_RE =
  /^(?:Error:\s*)?(?:working-dir path does not exist;\s*chat\.create not called|invalid_working_dir|invalid_chat_mode|kickoff_bot_not_selected|--kickoff-bot\b[^\n]*requires|Usage:\s*botmux\s+create-group)\b/im;
const ANY_CHAT_ID_IN_OUTPUT_RE = /\boc_[A-Za-z0-9_-]{4,128}\b/;

function makeDeterministicRequestId(seed: string): string {
  const hash = createHash('sha256').update(seed).digest('hex').slice(0, 32);
  return `gh_${hash}`;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Returns true iff a PR group record has completed every required orchestration
 * step for `rule` (chat created, kickoff verified when present, top notice pinned
 * when required, share-link PR comment posted when required).
 */
export function isPrGroupComplete(
  record: PrGroupRecord | undefined,
  rule: RepoRule,
): boolean {
  if (!record || record.status !== 'active' || !record.chatId) {
    return false;
  }
  if (record.createAttempt?.outcomeUnknown) {
    return false;
  }
  if ((rule.kickoffBotAppId || rule.setTopNotice) && !record.kickoffMessageId) {
    return false;
  }
  if (record.kickoffMessageId && record.kickoffVerified !== true) {
    return false;
  }
  if (rule.setTopNotice && !record.topNoticeSet) {
    return false;
  }
  if (rule.postShareLinkToPr && record.shareLink && !record.shareLinkPosted) {
    return false;
  }
  return true;
}

/**
 * Checks whether an existing Feishu group name matches the exact expected group
 * name or starts with the trusted canonical prefix `[owner/repo#N]`,
 * `PR #N owner/repo`, or the bounded hashed canonical prefix for long owner/repo
 * names. Strictly anchored to the start so untrusted PR titles mentioning other
 * PR numbers (e.g. "see owner/repo#51") can NEVER hijack deduplication!
 */
export function groupNameMatchesPr(
  existingName: string | undefined,
  expectedGroupName: string,
  repo: string,
  prNumber: number,
): boolean {
  if (!existingName) return false;
  const normExisting = existingName.trim();
  const normExpected = expectedGroupName.trim();
  if (normExisting === normExpected) return true;

  const repoEsc = escapeRegExp(repo);
  // Closing ']' is already an unambiguous delimiter, so no extra trailing whitespace lookahead needed.
  const canonicalPrefix = makeCanonicalPrGroupPrefix(repo, prNumber);
  const canonicalPrefixEsc = escapeRegExp(canonicalPrefix);
  const canonicalRe = new RegExp(`^${canonicalPrefixEsc}`, 'i');
  if (canonicalRe.test(normExisting)) return true;

  const bracketPrefixRe = new RegExp(`^\\[${repoEsc}#${prNumber}\\]`, 'i');
  if (bracketPrefixRe.test(normExisting)) return true;

  const prPrefixRe = new RegExp(`^PR\\s*#${prNumber}\\s+${repoEsc}(?=$|[\\s\\-:])`, 'i');
  return prPrefixRe.test(normExisting);
}

/**
 * Verifies kickoff readback text matches the target PR strictly via trusted
 * envelope/header markers OUTSIDE untrusted `<title>` / `<body>` content:
 * 1. `<untrusted_pr_metadata ... repo="owner/repo" pr_number="N" ...>`
 * 2. Line-anchored `PR: owner/repo#N` appearing BEFORE `<untrusted_pr_metadata`
 * Never matches arbitrary substrings inside untrusted PR titles/bodies!
 */
export function kickoffTextMatchesPr(
  text: string | null | undefined,
  repo: string,
  prNumber: number,
): boolean {
  if (!text) return false;
  const repoEsc = escapeRegExp(repo);
  // 1. Trusted XML opening envelope attribute check
  const xmlEnvelopeRe = new RegExp(
    `<untrusted_pr_metadata\\b[^>]*\\brepo="${repoEsc}"[^>]*\\bpr_number="${prNumber}"\\b`,
    'i',
  );
  if (xmlEnvelopeRe.test(text)) return true;

  // 2. Trusted header line strictly BEFORE <untrusted_pr_metadata (or whole message if no XML)
  const xmlIdx = text.indexOf('<untrusted_pr_metadata');
  const trustedPrefix = xmlIdx >= 0 ? text.slice(0, xmlIdx) : text;
  const headerLineRe = new RegExp(`^PR:\\s*${repoEsc}#${prNumber}\\s*$`, 'im');
  return headerLineRe.test(trustedPrefix);
}

export function buildShareLinkPrComment(shareLink: string, chatId: string): string {
  // Strictly zero untrusted PR metadata in outgoing GitHub comments (prevents ChatOps /merge injection).
  return [
    `A Botmux review group has been created for this pull request.`,
    ``,
    `- Join review group: ${shareLink}`,
    ``,
    `<!-- botmux-plugin-github:share-link:${chatId} -->`,
  ].join('\n');
}

/**
 * Crash-safe Botmux HostBridge supporting both Phase 1 current Botmux core
 * and upcoming Botmux core IPC PRs seamlessly:
 * 1. All 127.0.0.1 daemon IPC uses node:http (bypassing Bun $http_proxy 403 bug)
 *    with ~/.botmux/.dashboard-secret HMAC auth.
 * 2. Persists `creating` lock -> queries GET /api/groups for duplicate prevention ->
 *    calls POST /api/groups/create (with kickoffBotLarkAppId/kickoffPrompt/ownerNotice
 *    for new core, automatic fallback to step-by-step IPC message or botmux create-group CLI
 *    on current core) -> immediately persists chatId (even on 502 partial failure).
 * 3. Readback-verifies kickoffMessageId matches current PR number.
 * 4. Sets top notice: tries POST /api/groups/:chatId/top-notice (new core), falls back
 *    on 404/405/501 to brand-aware open.feishu.cn / open.larksuite.com tenant token +
 *    put_top_notice (NEVER calls lark-cli --as user).
 * 5. Optional idempotent PR share-link comment & follow-up commit/close updates.
 */
export class HostBridge {
  private readonly stateStore: StateStore;
  private readonly discovery?: DiscoveryOptions;
  private readonly registry: SecretRegistry;
  private readonly larkClient: LarkOpenApiClient;
  private readonly cliExec: CliExecFn;
  private readonly unknownOutcomeSettleMs: number;
  private readonly now: () => number;

  constructor(opts: HostBridgeOptions) {
    this.stateStore = opts.stateStore;
    this.discovery = opts.discovery;
    this.registry = opts.registry ?? defaultSecretRegistry;
    this.larkClient =
      opts.larkClient ??
      new LarkOpenApiClient({
        proxy: opts.proxy,
        registry: this.registry,
        now: opts.now,
      });
    this.cliExec = opts.cliExec ?? defaultCliExec;
    this.unknownOutcomeSettleMs = Math.max(
      0,
      opts.unknownOutcomeSettleMs ?? DEFAULT_UNKNOWN_OUTCOME_SETTLE_MS,
    );
    this.now = opts.now ?? (() => Date.now());
  }

  private async daemonRequest(opts: {
    ipcPort: number;
    secret: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE';
    path: string;
    body?: unknown;
    timeoutMs?: number;
  }): Promise<{ status: number; json: unknown; rawText: string }> {
    const authHeaders = signDaemonIpcHeaders(
      opts.secret,
      opts.method,
      opts.path,
      opts.ipcPort,
      this.now(),
    );
    const bodyStr = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
    const headers: Record<string, string> = {
      ...authHeaders,
      ...(bodyStr !== undefined ? { 'Content-Type': 'application/json' } : {}),
    };
    const res = await loopbackRequest({
      host: '127.0.0.1',
      port: opts.ipcPort,
      method: opts.method,
      path: opts.path,
      headers,
      body: bodyStr,
      timeoutMs: opts.timeoutMs ?? 20_000,
    });
    const rawText = res.body.toString('utf8');
    let json: unknown = null;
    try {
      json = rawText ? JSON.parse(rawText) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json, rawText };
  }

  async listCreatorGroups(
    creatorLarkAppId: string,
  ): Promise<{ groups: DaemonGroupItem[]; ipcPort: number; secret: string } | null> {
    const daemons = await discoverOnlineDaemons(this.discovery);
    const daemon = daemons.get(creatorLarkAppId);
    if (!daemon) return null;
    const secret = await loadDashboardSecret(this.discovery, this.registry);
    if (!secret) return null;

    const resp = await this.daemonRequest({
      ipcPort: daemon.ipcPort,
      secret,
      method: 'GET',
      path: '/api/groups',
      timeoutMs: 15_000,
    });
    if (resp.status !== 200 || !resp.json || typeof resp.json !== 'object') {
      throw new Error(
        `Daemon GET /api/groups failed (${resp.status}): ${this.registry.redactString(resp.rawText.slice(0, 200))}`,
      );
    }
    const respObj = resp.json as { ok?: unknown; chats?: unknown; error?: unknown };
    if (respObj.ok === false || !Array.isArray(respObj.chats)) {
      throw new Error(
        `Daemon GET /api/groups returned invalid payload: ${this.registry.redactString(String(respObj.error ?? resp.rawText.slice(0, 200)))}`,
      );
    }
    const groups: DaemonGroupItem[] = respObj.chats
      .filter(
        (c): c is DaemonGroupItem =>
          Boolean(c && typeof c === 'object' && typeof (c as DaemonGroupItem).chatId === 'string'),
      )
      .filter(c => !c.chatStatus || c.chatStatus === 'normal');
    return { groups, ipcPort: daemon.ipcPort, secret };
  }

  /**
   * Resolves the creator-bot-scoped Feishu open_id for a target kickoff bot.
   * NEVER substitutes a foreign app's self-view botOpenId from bots-info.json.
   */
  private async resolveCreatorScopedKickoffOpenId(
    creatorLarkAppId: string,
    kickoffBotAppId: string,
    chatId: string,
    ipcPort: number,
    secret: string,
  ): Promise<string | null> {
    const botsInfo = await loadBotsInfo(this.discovery);
    const targetInfo = botsInfo.find(b => b.larkAppId === kickoffBotAppId);
    const targetName = targetInfo?.botName?.trim();

    // Primary: <dataDir>/bot-openids-<creatorLarkAppId>.json keyed by trimmed botName
    if (targetName) {
      const scopedMap = await loadCreatorScopedBotOpenIds(creatorLarkAppId, this.discovery);
      const mapped = Object.hasOwn(scopedMap, targetName) ? scopedMap[targetName] : undefined;
      if (
        mapped &&
        OPEN_ID_RE.test(mapped) &&
        !(kickoffBotAppId !== creatorLarkAppId && targetInfo?.botOpenId && mapped === targetInfo.botOpenId)
      ) {
        return mapped;
      }
    }

    // Fallback: query creator daemon's GET /api/groups/:chatId/members-display
    // STRICTLY reject self-view / non-mentionable foreign botOpenId entries!
    if (targetName) {
      try {
        const resp = await this.daemonRequest({
          ipcPort,
          secret,
          method: 'GET',
          path: `/api/groups/${encodeURIComponent(chatId)}/members-display`,
          timeoutMs: 10_000,
        });
        if (resp.status === 200 && resp.json && typeof resp.json === 'object') {
          const members = (resp.json as { members?: unknown }).members;
          if (Array.isArray(members)) {
            for (const m of members) {
              if (!m || typeof m !== 'object') continue;
              const rec = m as Record<string, unknown>;
              if (rec.mentionable === false || rec.mentionSource === 'self') continue;
              const name = typeof rec.name === 'string' ? rec.name.trim() : '';
              const id =
                typeof rec.openId === 'string'
                  ? rec.openId.trim()
                  : typeof rec.memberId === 'string'
                    ? rec.memberId.trim()
                    : '';
              const type = typeof rec.memberType === 'string' ? rec.memberType : '';
              if (
                kickoffBotAppId !== creatorLarkAppId &&
                targetInfo?.botOpenId &&
                id === targetInfo.botOpenId
              ) {
                // Never substitute foreign app's self-view botOpenId
                continue;
              }
              if (name === targetName && OPEN_ID_RE.test(id) && (!type || type === 'bot')) {
                return id;
              }
            }
          }
        }
      } catch {
        // Best-effort
      }
    }

    return null;
  }

  /**
   * Sends a plain-text message through creator daemon IPC POST /api/groups/:chatId/messages
   * with strict 2-key body `{ requestId, content }` (<= 8192 UTF-8 bytes) and idempotent retry.
   */
  async sendGroupMessage(opts: {
    creatorLarkAppId: string;
    chatId: string;
    requestId: string;
    content: string;
    ipcPort?: number;
    secret?: string;
  }): Promise<{ messageId: string; replayed: boolean }> {
    if (!CHAT_ID_RE.test(opts.chatId)) {
      throw new Error(`Invalid chatId: ${opts.chatId}`);
    }
    if (Buffer.byteLength(opts.content, 'utf8') > MAX_IPC_TEXT_BYTES) {
      throw new Error(`Message exceeds ${MAX_IPC_TEXT_BYTES} UTF-8 bytes`);
    }

    let ipcPort = opts.ipcPort;
    let secret = opts.secret;
    if (!ipcPort) {
      const daemons = await discoverOnlineDaemons(this.discovery);
      ipcPort = daemons.get(opts.creatorLarkAppId)?.ipcPort;
    }
    if (!secret) {
      secret = (await loadDashboardSecret(this.discovery, this.registry)) ?? undefined;
    }
    if (!ipcPort || !secret) {
      throw new Error(`Creator daemon IPC unavailable for ${opts.creatorLarkAppId}`);
    }

    // Strict 2-key body required by Botmux request-bound-group-send
    const payload = {
      requestId: opts.requestId,
      content: opts.content,
    };

    let lastErr = '';
    for (let attempt = 0; attempt < 2; attempt++) {
      const resp = await this.daemonRequest({
        ipcPort,
        secret,
        method: 'POST',
        path: `/api/groups/${encodeURIComponent(opts.chatId)}/messages`,
        body: payload,
        timeoutMs: 15_000,
      });

      if (resp.status === 200 && resp.json && typeof resp.json === 'object') {
        const body = resp.json as { messageId?: unknown; replayed?: unknown };
        if (typeof body.messageId === 'string' && MESSAGE_ID_RE.test(body.messageId)) {
          return { messageId: body.messageId, replayed: body.replayed === true };
        }
      }

      const errObj = (resp.json && typeof resp.json === 'object' ? resp.json : {}) as {
        error?: string;
        retryable?: boolean;
      };
      lastErr = `POST /api/groups/${opts.chatId}/messages failed (${resp.status} ${errObj.error ?? ''})`;

      // Never mint a new requestId or retry on 409 conflict / outcome_unknown or non-retryable 502.
      if (resp.status === 409) {
        throw new Error(`${lastErr} (halting retry to prevent duplicate message)`);
      }
      if (resp.status === 502 && errObj.retryable !== true) {
        throw new Error(lastErr);
      }
      if (resp.status === 503 || (resp.status === 502 && errObj.retryable === true)) {
        if (attempt === 0) {
          await new Promise(r => setTimeout(r, 400));
          continue;
        }
      }
      throw new Error(lastErr);
    }

    throw new Error(lastErr || 'Failed to send group message');
  }

  private async findExistingKickoffMessage(
    chatId: string,
    repo: string,
    prNumber: number,
    ipcPort: number,
    secret: string,
  ): Promise<string | null> {
    try {
      const resp = await this.daemonRequest({
        ipcPort,
        secret,
        method: 'GET',
        path: `/api/groups/${encodeURIComponent(chatId)}/messages`,
        timeoutMs: 10_000,
      });
      if (resp.status !== 200 || !resp.json || typeof resp.json !== 'object') {
        return null;
      }
      const messages = (resp.json as { messages?: unknown }).messages;
      if (!Array.isArray(messages)) return null;
      for (const m of messages) {
        if (!m || typeof m !== 'object') continue;
        const rec = m as { messageId?: unknown; preview?: unknown; deleted?: unknown };
        if (rec.deleted === true) continue;
        if (
          typeof rec.messageId === 'string' &&
          MESSAGE_ID_RE.test(rec.messageId) &&
          typeof rec.preview === 'string' &&
          kickoffTextMatchesPr(rec.preview, repo, prNumber)
        ) {
          return rec.messageId;
        }
      }
    } catch {
      // Ignore scan error
    }
    return null;
  }

  private async verifyKickoffMessageReadback(
    chatId: string,
    kickoffMessageId: string,
    repo: string,
    prNumber: number,
    ipcPort: number,
    secret: string,
  ): Promise<{ verified: boolean; reason?: string }> {
    const resp = await this.daemonRequest({
      ipcPort,
      secret,
      method: 'GET',
      path: `/api/groups/${encodeURIComponent(chatId)}/messages/${encodeURIComponent(kickoffMessageId)}`,
      timeoutMs: 10_000,
    });

    if (resp.status === 200 && resp.json && typeof resp.json === 'object') {
      const data = resp.json as DaemonReadMessageResponse;
      if (data.deleted === true) {
        return { verified: false, reason: 'kickoff_message_deleted' };
      }
      if (data.chatId && data.chatId !== chatId) {
        return { verified: false, reason: 'kickoff_message_chat_mismatch' };
      }
      if (kickoffTextMatchesPr(data.text, repo, prNumber)) {
        return { verified: true };
      }
      return { verified: false, reason: 'kickoff_message_pr_mismatch' };
    }

    // Fallback to message list scan if single-message readback route is unavailable.
    if (resp.status === 404 || resp.status === 405 || resp.status === 501) {
      const found = await this.findExistingKickoffMessage(chatId, repo, prNumber, ipcPort, secret);
      if (found === kickoffMessageId) {
        return { verified: true };
      }
    }

    return { verified: false, reason: `kickoff_readback_http_${resp.status}` };
  }

  private async setTopNoticeDualPath(opts: {
    creatorLarkAppId: string;
    chatId: string;
    messageId: string;
    ipcPort?: number;
    secret?: string;
  }): Promise<{ ok: boolean; pathUsed: 'ipc' | 'lark_openapi' | 'none'; error?: string }> {
    // Path 1: Upcoming core daemon IPC POST /api/groups/:chatId/top-notice
    if (opts.ipcPort && opts.secret) {
      try {
        const resp = await this.daemonRequest({
          ipcPort: opts.ipcPort,
          secret: opts.secret,
          method: 'POST',
          path: `/api/groups/${encodeURIComponent(opts.chatId)}/top-notice`,
          body: { messageId: opts.messageId },
          timeoutMs: 10_000,
        });
        if (resp.status === 200) {
          const body = (resp.json && typeof resp.json === 'object' ? resp.json : {}) as {
            ok?: boolean;
          };
          if (body.ok !== false) {
            return { ok: true, pathUsed: 'ipc' };
          }
        }
        // Only fall back to Lark Open API if the IPC endpoint is absent/unimplemented
        if (resp.status !== 404 && resp.status !== 405 && resp.status !== 501) {
          return {
            ok: false,
            pathUsed: 'ipc',
            error: `Daemon top-notice IPC returned HTTP ${resp.status}`,
          };
        }
      } catch {
        // Fall through to Lark Open API fallback
      }
    }

    // Path 2: Direct brand-aware Feishu / Lark Open Platform API (NEVER lark-cli --as user)
    const bots = await loadBotsConfig(this.discovery, this.registry);
    const bot = bots.find(b => b.larkAppId === opts.creatorLarkAppId);
    if (!bot || !bot.larkAppSecret || bot.apiOnly) {
      return {
        ok: false,
        pathUsed: 'none',
        error: `Cannot set top notice: creator bot ${opts.creatorLarkAppId} missing larkAppSecret in bots.json`,
      };
    }

    const brand: LarkBrand = bot.brand;
    const res = await this.larkClient.putChatTopNotice({
      appId: bot.larkAppId,
      appSecret: bot.larkAppSecret,
      brand,
      chatId: opts.chatId,
      messageId: opts.messageId,
    });
    if (res.ok) {
      return { ok: true, pathUsed: 'lark_openapi' };
    }
    return { ok: false, pathUsed: 'lark_openapi', error: res.error };
  }

  private async createGroupViaCliFallback(opts: {
    rule: RepoRule;
    groupName: string;
    kickoffPrompt: string;
  }): Promise<{
    chatId: string;
    kickoffMessageId: string | null;
    kickoffError: string | null;
  }> {
    const bin = resolveBotmuxBin(this.discovery);
    const allBots = [opts.rule.creatorBotAppId];
    for (const id of opts.rule.memberBotAppIds) {
      if (!allBots.includes(id)) allBots.push(id);
    }
    if (opts.rule.kickoffBotAppId && !allBots.includes(opts.rule.kickoffBotAppId)) {
      allBots.push(opts.rule.kickoffBotAppId);
    }

    // Use --flag=value syntax for user-derived strings so leading dashes cannot inject flags.
    const args: string[] = [];
    for (const botId of allBots) {
      args.push(`--bot=${botId}`);
    }
    args.push(`--name=${opts.groupName}`);
    if (opts.rule.chatMode) {
      args.push(`--chat-mode=${opts.rule.chatMode}`);
    }
    if (opts.rule.bindWorkingDir) {
      args.push(`--working-dir=${opts.rule.bindWorkingDir}`);
    }

    // botmux create-group --kickoff-bot expects self-view botOpenId from bots-info.json
    if (opts.rule.kickoffBotAppId) {
      const botsInfo = await loadBotsInfo(this.discovery);
      const kickoffInfo = botsInfo.find(b => b.larkAppId === opts.rule.kickoffBotAppId);
      if (kickoffInfo?.botOpenId) {
        args.push(`--kickoff-bot=${kickoffInfo.botOpenId}`);
        args.push(`--kickoff-prompt=${opts.kickoffPrompt}`);
      }
    }
    args.push('--json-status');

    // Strip BUN_BE_BUN and BOTMUX_SESSION_ID so compiled standalone binary runs normally.
    const env: Record<string, string | undefined> = { ...process.env };
    delete env.BUN_BE_BUN;
    delete env.BOTMUX_SESSION_ID;

    const result = await this.cliExec(bin, ['create-group', ...args], {
      timeoutMs: 45_000,
      env,
    });

    const lines = result.stdout
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(Boolean);

    let chatId = '';
    let kickoffMessageId: string | null = null;
    let kickoffError: string | null = null;
    let structuredDefinitelyNotCreated = false;

    const tryInspectStatusJson = (rawLine: string) => {
      if (!rawLine || !rawLine.startsWith('{')) return;
      try {
        const parsed = JSON.parse(rawLine) as {
          chatId?: unknown;
          chatCreated?: unknown;
          definitelyNotCreated?: unknown;
          kickoffMessageId?: unknown;
          kickoffError?: unknown;
        };
        if (!chatId && typeof parsed.chatId === 'string' && CHAT_ID_RE.test(parsed.chatId)) {
          chatId = parsed.chatId;
        }
        if (parsed.definitelyNotCreated === true || parsed.chatCreated === false) {
          structuredDefinitelyNotCreated = true;
        }
        if (typeof parsed.kickoffMessageId === 'string' && MESSAGE_ID_RE.test(parsed.kickoffMessageId)) {
          kickoffMessageId = parsed.kickoffMessageId;
        }
        if (typeof parsed.kickoffError === 'string') {
          kickoffError = parsed.kickoffError;
        }
      } catch {
        // Ignore malformed JSON line
      }
    };

    // Scan ALL stdout lines for bare chatId or JSON status objects
    for (const line of lines) {
      if (!chatId && CHAT_ID_RE.test(line)) {
        chatId = line;
      }
      tryInspectStatusJson(line);
    }
    for (const sLine of result.stderr.split(/\r?\n/).map(l => l.trim()).filter(Boolean)) {
      tryInspectStatusJson(sLine);
    }

    // Even if exitCode !== 0, if chatId was flushed on stdout, return it so we NEVER create a duplicate!
    if (!chatId) {
      const safeErr = `botmux create-group CLI failed (exit ${result.exitCode}): ${this.registry.redactString(result.stderr.slice(0, 300))}`;
      const wasKilledOrSignaled = Boolean(result.killed || result.signal);
      const anyChatIdMentioned =
        ANY_CHAT_ID_IN_OUTPUT_RE.test(result.stdout) || ANY_CHAT_ID_IN_OUTPUT_RE.test(result.stderr);
      const binaryNotLaunched = result.errorCode === 'ENOENT' || result.errorCode === 'EACCES';
      const deterministicPreCreate =
        !wasKilledOrSignaled &&
        !anyChatIdMentioned &&
        (structuredDefinitelyNotCreated ||
          binaryNotLaunched ||
          DEFINITE_CLI_PRECREATE_ERR_RE.test(result.stderr));
      if (deterministicPreCreate) {
        throw new CliPreCreateError(safeErr);
      }
      throw new Error(safeErr);
    }

    return { chatId, kickoffMessageId, kickoffError };
  }

  private async postShareLinkIdempotently(opts: {
    githubClient: GitHubClient;
    pr: PullRequestInfo;
    chatId: string;
    shareLink: string;
    existingCommentId?: number;
  }): Promise<{ posted: boolean; commentId?: number }> {
    const normalizedLink = normalizeTrustedLarkShareLink(opts.shareLink);
    if (!normalizedLink) {
      return { posted: false };
    }
    const [owner, repo] = opts.pr.repo.split('/');
    if (!owner || !repo) return { posted: false };

    const marker = `<!-- botmux-plugin-github:share-link:${opts.chatId} -->`;

    // Fast path: if we previously persisted shareLinkCommentId, verify it directly
    if (opts.existingCommentId) {
      const existing = await opts.githubClient.getIssueComment(owner, repo, opts.existingCommentId);
      if (existing && existing.body.includes(marker)) {
        return { posted: true, commentId: existing.id };
      }
    }

    // Paginate ALL issue comments (stopping early as soon as marker is found!)
    let matchedId: number | undefined;
    const scan = await opts.githubClient.listIssueComments(owner, repo, opts.pr.number, {
      stopWhen: c => {
        if (c.body.includes(marker)) {
          matchedId = c.id;
          return true;
        }
        return false;
      },
    });
    if (matchedId !== undefined) {
      return { posted: true, commentId: matchedId };
    }
    if (scan.truncated) {
      throw new Error(
        `Refusing to post share-link comment for ${opts.pr.repo}#${opts.pr.number}: comment history scan was truncated before verifying absence of existing marker`,
      );
    }

    const commentBody = buildShareLinkPrComment(normalizedLink, opts.chatId);
    const created = await opts.githubClient.createIssueComment(owner, repo, opts.pr.number, commentBody);
    return { posted: true, commentId: created.id || undefined };
  }

  /**
   * Executes the full crash-safe PR review group orchestration flow under a
   * cross-process exclusive per-PR lock:
   * - Mutually exclusive across separate HostBridge / CLI / service processes
   * - Queries creator daemon GET /api/groups before creating even if state was wiped
   * - Tracks createAttempt.outcomeUnknown so a dropped IPC response NEVER blindly
   *   switches to CLI fallback (must first verify via GET /api/groups!)
   * - Persists chatId immediately upon creation (including partial 502 responses)
   * - Refuses to pin top-notice or mark active until kickoff readback & required
   *   steps succeed; partial failures remain resumable without creating a 2nd group
   */
  async ensurePrReviewGroup(opts: {
    rule: RepoRule;
    pr: PullRequestInfo;
    githubClient: GitHubClient;
  }): Promise<GroupOrchestrationResult> {
    const prKey = makePrKey(opts.rule.repo, opts.pr.number);
    const lockHash = createHash('sha256').update(prKey).digest('hex').slice(0, 24);
    const prLockPath = join(this.stateStore.pluginHome, 'locks', `pr-${lockHash}.lock`);
    const prLock = await acquireSecureLock(prLockPath, {
      timeoutMs: 45_000,
      staleMs: 90_000,
      pollMs: 30,
      now: this.now,
    });

    try {
      return await this.ensurePrReviewGroupLocked(opts, prLock);
    } finally {
      await prLock.release();
    }
  }

  private async ensurePrReviewGroupLocked(
    opts: {
      rule: RepoRule;
      pr: PullRequestInfo;
      githubClient: GitHubClient;
    },
    prLock: { verifyOwned(): Promise<boolean> },
  ): Promise<GroupOrchestrationResult> {
    const { rule, pr, githubClient } = opts;
    const prKey = makePrKey(rule.repo, pr.number);
    const groupName = renderSafeGroupName(rule.groupNameTemplate, pr);
    const kickoffPromptBase = buildKickoffPrompt(rule.kickoffPromptTemplate, pr);
    const warnings: string[] = [];

    // Validate creator, kickoff & member bots against bots.json (reject apiOnly bots)
    const botsConfig = await loadBotsConfig(this.discovery, this.registry);
    const creatorCfg = botsConfig.find(b => b.larkAppId === rule.creatorBotAppId);
    if (creatorCfg?.apiOnly) {
      throw new Error(`Creator bot ${rule.creatorBotAppId} is apiOnly and cannot create Feishu/Lark groups`);
    }
    if (rule.kickoffBotAppId) {
      const kickoffCfg = botsConfig.find(b => b.larkAppId === rule.kickoffBotAppId);
      if (kickoffCfg?.apiOnly) {
        throw new Error(`Kickoff bot ${rule.kickoffBotAppId} is apiOnly and cannot join Feishu/Lark groups`);
      }
    }
    const apiOnlyBotIds = new Set(botsConfig.filter(b => b.apiOnly).map(b => b.larkAppId));
    const validMemberBotAppIds = rule.memberBotAppIds.filter(id => !apiOnlyBotIds.has(id));

    // Step 1: Load or persist `creating` lock BEFORE calling any external mutation API
    const nowIso = new Date(this.now()).toISOString();
    let record = await this.stateStore.update(state => {
      const existing = state.prGroups[prKey];
      if (existing) {
        existing.updatedAt = nowIso;
        existing.lastHeadSha = pr.headSha;
        if (existing.status === 'closed') {
          existing.lifecycleGeneration = (existing.lifecycleGeneration ?? 1) + 1;
          existing.status = 'creating';
        } else if (!isPrGroupComplete(existing, rule)) {
          existing.status = 'creating';
        }
        return { ...existing };
      }
      const created: PrGroupRecord = {
        status: 'creating',
        repo: rule.repo,
        prNumber: pr.number,
        groupName,
        creatorLarkAppId: rule.creatorBotAppId,
        ...(rule.kickoffBotAppId ? { kickoffBotAppId: rule.kickoffBotAppId } : {}),
        topNoticeSet: false,
        lifecycleGeneration: 1,
        lastHeadSha: pr.headSha,
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      state.prGroups[prKey] = created;
      return { ...created };
    });

    const daemons = await discoverOnlineDaemons(this.discovery);
    const creatorDaemon = daemons.get(rule.creatorBotAppId);
    const dashboardSecret = await loadDashboardSecret(this.discovery, this.registry);
    const canUseDaemonIpc = Boolean(creatorDaemon && dashboardSecret);

    let reusedExisting = Boolean(record.chatId);

    // Step 2: If no chatId recorded yet, check creator daemon GET /api/groups to prevent duplicate groups!
    // Exclude any chatId already bound to a DIFFERENT PR in state.prGroups.
    let verifiedEmptyViaDaemonGroups = false;
    if (!record.chatId && canUseDaemonIpc) {
      const currentState = await this.stateStore.load();
      const chatIdsBoundToOtherPrs = new Set<string>();
      for (const [k, g] of Object.entries(currentState.prGroups)) {
        if (k !== prKey && g.chatId) {
          chatIdsBoundToOtherPrs.add(g.chatId);
        }
      }
      const listed = await this.listCreatorGroups(rule.creatorBotAppId);
      if (listed) {
        const matched = listed.groups.find(
          g =>
            !chatIdsBoundToOtherPrs.has(g.chatId) &&
            groupNameMatchesPr(g.name, groupName, rule.repo, pr.number),
        );
        if (matched && CHAT_ID_RE.test(matched.chatId)) {
          reusedExisting = true;
          record = await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.chatId = matched.chatId;
            cur.groupName = matched.name || groupName;
            delete cur.createAttempt;
            cur.updatedAt = new Date(this.now()).toISOString();
            return { ...cur };
          });
          await this.stateStore.appendEvent({
            level: 'info',
            kind: 'group_reused_existing',
            repo: rule.repo,
            prNumber: pr.number,
            chatId: matched.chatId,
            message: `Adopted existing group ${matched.chatId} from GET /api/groups for ${prKey}`,
          });
        } else {
          verifiedEmptyViaDaemonGroups = true;
        }
      }
    }

    // Fail closed if a prior create attempt had an unknown outcome (e.g. socket reset/timeout):
    // 1. If GET /api/groups already found & adopted the group above, record.chatId is now set and createAttempt was cleared.
    // 2. If creator daemon GET /api/groups is unavailable -> ALWAYS fail closed.
    // 3. Even if GET /api/groups returned empty, an in-flight create on the daemon may still be committing
    //    (real core does not cancel createChat on client socket drop!). Keep createAttempt.outcomeUnknown=true
    //    and fail closed until the full safety window (`unknownOutcomeSettleMs`) has elapsed!
    if (!record.chatId && record.createAttempt?.outcomeUnknown) {
      if (!verifiedEmptyViaDaemonGroups) {
        const errMsg = `Prior ${record.createAttempt.path} group creation attempt for ${prKey} has unknown outcome and creator daemon GET /api/groups is currently unavailable; refusing to switch execution path or retry create to prevent duplicate groups.`;
        await this.stateStore.update(state => {
          const cur = state.prGroups[prKey];
          if (cur) {
            cur.lastError = errMsg;
            cur.updatedAt = new Date(this.now()).toISOString();
          }
        });
        throw new Error(errMsg);
      }

      const startedMs = Date.parse(record.createAttempt.startedAt);
      const nowMs = this.now();
      const timestampInvalidOrFuture = !Number.isFinite(startedMs) || nowMs < startedMs;
      const elapsedMs = timestampInvalidOrFuture ? 0 : nowMs - startedMs;
      if (timestampInvalidOrFuture || elapsedMs < this.unknownOutcomeSettleMs) {
        const errMsg = `Prior ${record.createAttempt.path} group creation attempt for ${prKey} has unknown outcome (elapsed ${elapsedMs}ms < safety settle window ${this.unknownOutcomeSettleMs}ms); keeping fail-closed because empty GET /api/groups cannot rule out an in-flight create.`;
        await this.stateStore.update(state => {
          const cur = state.prGroups[prKey];
          if (cur) {
            cur.lastError = errMsg;
            cur.updatedAt = new Date(this.now()).toISOString();
          }
        });
        throw new Error(errMsg);
      }

      // Past full safety settle window AND GET /api/groups confirmed no matching group exists
      record = await this.stateStore.update(state => {
        const cur = state.prGroups[prKey]!;
        delete cur.createAttempt;
        cur.updatedAt = new Date(this.now()).toISOString();
        return { ...cur };
      });
    }

    // Step 3: Create group ONLY if chatId is still unknown
    if (!record.chatId) {
      // Fencing check: confirm we still own the per-PR mutex right before mutating external state
      if (!(await prLock.verifyOwned())) {
        throw new Error(`Lost ownership of per-PR lock for ${prKey} before group creation`);
      }

      const larkAppIds = [rule.creatorBotAppId];
      for (const id of validMemberBotAppIds) {
        if (!larkAppIds.includes(id)) larkAppIds.push(id);
      }
      if (rule.kickoffBotAppId && !larkAppIds.includes(rule.kickoffBotAppId)) {
        larkAppIds.push(rule.kickoffBotAppId);
      }

      const attemptId = randomBytes(8).toString('hex');

      if (canUseDaemonIpc && creatorDaemon && dashboardSecret) {
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.createAttempt = {
            path: 'ipc',
            idempotencyKey: attemptId,
            startedAt: new Date(this.now()).toISOString(),
            outcomeUnknown: true,
          };
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });

        const userOpenIds = creatorDaemon.resolvedAllowedUsers.filter(u => u.startsWith('ou_'));
        const ownerUnionIds = creatorDaemon.resolvedAllowedUsers.filter(u => u.startsWith('on_'));

        const createBody: Record<string, unknown> = {
          name: groupName,
          larkAppIds,
          chatMode: rule.chatMode,
          idempotencyKey: attemptId,
          ...(rule.bindWorkingDir ? { bindWorkingDir: rule.bindWorkingDir } : {}),
          ...(userOpenIds.length > 0 ? { userOpenIds } : {}),
          ...(ownerUnionIds.length > 0 ? { ownerUnionIds } : {}),
          ...(userOpenIds[0]
            ? { transferOwnerTo: userOpenIds[0] }
            : ownerUnionIds[0]
              ? { transferOwnerUnionId: ownerUnionIds[0] }
              : {}),
          ...(larkAppIds.length >= 2 ? { botCollaboration: true } : {}),
          ...(rule.kickoffBotAppId
            ? {
                kickoffBotLarkAppId: rule.kickoffBotAppId,
                kickoffPrompt: kickoffPromptBase,
              }
            : {}),
          ownerNotice: false,
        };

        let resp: { status: number; json: unknown; rawText: string };
        try {
          resp = await this.daemonRequest({
            ipcPort: creatorDaemon.ipcPort,
            secret: dashboardSecret,
            method: 'POST',
            path: '/api/groups/create',
            body: createBody,
            timeoutMs: 35_000,
          });
        } catch (err: unknown) {
          const code = (err as NodeJS.ErrnoException)?.code;
          if (code === 'ECONNREFUSED') {
            // Connection never reached daemon -> definitely not created; clear unknown outcome
            await this.stateStore.update(state => {
              const cur = state.prGroups[prKey];
              if (cur) {
                delete cur.createAttempt;
                cur.lastError = formatSafeError(err, this.registry);
                cur.updatedAt = new Date(this.now()).toISOString();
              }
            });
          } else {
            // Socket reset / timeout / aborted -> keep outcomeUnknown: true!
            await this.stateStore.update(state => {
              const cur = state.prGroups[prKey];
              if (cur) {
                cur.lastError = `IPC create outcome unknown: ${formatSafeError(err, this.registry)}`;
                cur.updatedAt = new Date(this.now()).toISOString();
              }
            });
          }
          throw err;
        }

        const body = (resp.json && typeof resp.json === 'object'
          ? resp.json
          : {}) as DaemonCreateGroupResponse;

        // CRITICAL: Immediately persist chatId even on HTTP 502 partial failure so retries NEVER double-create!
        if (typeof body.chatId === 'string' && CHAT_ID_RE.test(body.chatId)) {
          record = await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.chatId = body.chatId;
            delete cur.createAttempt;
            if (typeof body.shareLink === 'string' && body.shareLink) {
              cur.shareLink = body.shareLink;
            }
            if (typeof body.kickoffMessageId === 'string' && MESSAGE_ID_RE.test(body.kickoffMessageId)) {
              cur.kickoffMessageId = body.kickoffMessageId;
            }
            if (resp.status >= 400 && body.error) {
              cur.lastError = this.registry.redactString(body.error);
            }
            cur.updatedAt = new Date(this.now()).toISOString();
            return { ...cur };
          });

          await this.stateStore.appendEvent({
            level: resp.status === 200 ? 'info' : 'warn',
            kind: 'group_created',
            repo: rule.repo,
            prNumber: pr.number,
            chatId: body.chatId,
            message:
              resp.status === 200
                ? `Created group ${body.chatId} via daemon IPC`
                : `Persisted partial group ${body.chatId} from HTTP ${resp.status} response`,
          });

          if (resp.status >= 400) {
            warnings.push(
              `Group ${body.chatId} created with partial HTTP ${resp.status}: ${body.error ?? 'post-create warning'}`,
            );
          }
        } else {
          // Definite pre-create rejection (400/401/403/503 without chatId): safe to clear outcomeUnknown
          const definitePreCreate =
            resp.status === 400 || resp.status === 401 || resp.status === 403 || resp.status === 503;
          await this.stateStore.update(state => {
            const cur = state.prGroups[prKey];
            if (cur) {
              if (definitePreCreate) delete cur.createAttempt;
              cur.lastError = `POST /api/groups/create failed (${resp.status})`;
              cur.updatedAt = new Date(this.now()).toISOString();
            }
          });
          throw new Error(
            `POST /api/groups/create failed (${resp.status}): ${this.registry.redactString(body.error ?? resp.rawText.slice(0, 200))}`,
          );
        }
      } else {
        // Fallback when creator daemon IPC is unavailable (and NO prior unknown IPC attempt exists): botmux create-group CLI
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.createAttempt = {
            path: 'cli',
            idempotencyKey: attemptId,
            startedAt: new Date(this.now()).toISOString(),
            outcomeUnknown: true,
          };
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });

        let cliRes: {
          chatId: string;
          kickoffMessageId: string | null;
          kickoffError: string | null;
        };
        try {
          cliRes = await this.createGroupViaCliFallback({
            rule,
            groupName,
            kickoffPrompt: kickoffPromptBase,
          });
        } catch (err) {
          if (err instanceof CliPreCreateError) {
            // Definite pre-create validation failure before chat.create -> safe to clear unknown outcome!
            await this.stateStore.update(state => {
              const cur = state.prGroups[prKey];
              if (cur) {
                delete cur.createAttempt;
                cur.lastError = formatSafeError(err, this.registry);
                cur.updatedAt = new Date(this.now()).toISOString();
              }
            });
          } else {
            // Ambiguous CLI failure -> keep outcomeUnknown: true (fail closed!)
            await this.stateStore.update(state => {
              const cur = state.prGroups[prKey];
              if (cur) {
                cur.lastError = `CLI create outcome unknown: ${formatSafeError(err, this.registry)}`;
                cur.updatedAt = new Date(this.now()).toISOString();
              }
            });
          }
          throw err;
        }
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.chatId = cliRes.chatId;
          delete cur.createAttempt;
          if (cliRes.kickoffMessageId) {
            cur.kickoffMessageId = cliRes.kickoffMessageId;
          }
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
        if (cliRes.kickoffError) {
          warnings.push(`CLI kickoff warning: ${cliRes.kickoffError}`);
        }
        await this.stateStore.appendEvent({
          level: 'info',
          kind: 'group_created_cli_fallback',
          repo: rule.repo,
          prNumber: pr.number,
          chatId: cliRes.chatId,
          message: `Created group ${cliRes.chatId} via botmux create-group CLI fallback`,
        });
      }
    }

    const chatId = record.chatId!;

    // Step 4: Current-core kickoff fallback (when POST /api/groups/create returned kickoffMessageId == null)
    if (!record.kickoffMessageId && canUseDaemonIpc && creatorDaemon && dashboardSecret) {
      const alreadySentMsgId = await this.findExistingKickoffMessage(
        chatId,
        rule.repo,
        pr.number,
        creatorDaemon.ipcPort,
        dashboardSecret,
      );
      if (alreadySentMsgId) {
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.kickoffMessageId = alreadySentMsgId;
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
      } else {
        let prefix = '';
        if (rule.kickoffBotAppId) {
          const creatorScopedOpenId = await this.resolveCreatorScopedKickoffOpenId(
            rule.creatorBotAppId,
            rule.kickoffBotAppId,
            chatId,
            creatorDaemon.ipcPort,
            dashboardSecret,
          );
          if (creatorScopedOpenId) {
            prefix = `<at user_id="${creatorScopedOpenId}"></at> `;
          } else {
            warnings.push(
              `kickoff_bot_cross_app_openid_unknown for ${rule.kickoffBotAppId}; posting kickoff without @mention`,
            );
          }
        }

        const content = buildKickoffPrompt(rule.kickoffPromptTemplate, pr, {
          prefix,
          maxUtf8Bytes: MAX_IPC_TEXT_BYTES,
        });
        const requestId = makeDeterministicRequestId(`${prKey}:${chatId}:kickoff`);
        const sent = await this.sendGroupMessage({
          creatorLarkAppId: rule.creatorBotAppId,
          chatId,
          requestId,
          content,
          ipcPort: creatorDaemon.ipcPort,
          secret: dashboardSecret,
        });

        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.kickoffMessageId = sent.messageId;
          cur.kickoffVerified = false;
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
      }
    }

    // Step 5: Mandatory readback verification of kickoffMessageId before pinning top-notice or marking active!
    if (record.kickoffMessageId && !record.kickoffVerified) {
      if (canUseDaemonIpc && creatorDaemon && dashboardSecret) {
        let check: { verified: boolean; reason?: string };
        try {
          check = await this.verifyKickoffMessageReadback(
            chatId,
            record.kickoffMessageId,
            rule.repo,
            pr.number,
            creatorDaemon.ipcPort,
            dashboardSecret,
          );
        } catch (err) {
          check = { verified: false, reason: `kickoff_readback_error:${formatSafeError(err, this.registry)}` };
        }

        if (check.verified) {
          record = await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.kickoffVerified = true;
            cur.updatedAt = new Date(this.now()).toISOString();
            return { ...cur };
          });
        } else {
          const reason = check.reason ?? 'unverified';
          await this.stateStore.appendEvent({
            level: 'warn',
            kind: 'kickoff_readback_failed',
            repo: rule.repo,
            prNumber: pr.number,
            chatId,
            message: `Kickoff message ${record.kickoffMessageId} readback failed: ${reason}`,
          });

          const isDefiniteMismatch =
            reason === 'kickoff_message_pr_mismatch' ||
            reason === 'kickoff_message_deleted' ||
            reason === 'kickoff_message_chat_mismatch';

          await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            if (isDefiniteMismatch) {
              cur.kickoffMessageId = null;
            }
            cur.kickoffVerified = false;
            cur.status = 'creating';
            cur.lastError = reason;
            cur.updatedAt = new Date(this.now()).toISOString();
          });

          // Never pin top-notice or transition to active while kickoff is unverified!
          throw new Error(
            `Kickoff message readback not verified for ${prKey} in ${chatId}: ${reason}`,
          );
        }
      } else {
        // Cannot verify kickoff readback while creator daemon IPC is offline -> keep status='creating' and fail closed!
        await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.status = 'creating';
          cur.kickoffVerified = false;
          cur.lastError = 'kickoff_readback_daemon_offline';
          cur.updatedAt = new Date(this.now()).toISOString();
        });
        throw new Error(
          `Cannot verify kickoff message ${record.kickoffMessageId} while creator daemon is offline`,
        );
      }
    }

    // Step 6: Top-notice pinning (only after kickoff is verified; failure keeps status='creating' so retry resumes!)
    if (rule.setTopNotice && record.kickoffMessageId && !record.topNoticeSet) {
      const noticeRes = await this.setTopNoticeDualPath({
        creatorLarkAppId: rule.creatorBotAppId,
        chatId,
        messageId: record.kickoffMessageId,
        ipcPort: creatorDaemon?.ipcPort,
        secret: dashboardSecret ?? undefined,
      });
      if (noticeRes.ok) {
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.topNoticeSet = true;
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
        await this.stateStore.appendEvent({
          level: 'info',
          kind: 'top_notice_set',
          repo: rule.repo,
          prNumber: pr.number,
          chatId,
          message: `Pinned top notice ${record.kickoffMessageId} via ${noticeRes.pathUsed}`,
        });
      } else {
        const errMsg = noticeRes.error ?? 'top_notice_failed';
        await this.stateStore.appendEvent({
          level: 'warn',
          kind: 'top_notice_failed',
          repo: rule.repo,
          prNumber: pr.number,
          chatId,
          message: `Failed to pin top notice: ${errMsg}`,
        });
        await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.status = 'creating';
          cur.topNoticeSet = false;
          cur.lastError = errMsg;
          cur.updatedAt = new Date(this.now()).toISOString();
        });
        throw new Error(`Top notice pinning failed for ${prKey} in ${chatId}: ${errMsg}`);
      }
    }

    // Step 7: Optional idempotent PR share-link comment (paginates all comments + persists commentId!)
    if (rule.postShareLinkToPr && record.shareLink && !record.shareLinkPosted) {
      try {
        const res = await this.postShareLinkIdempotently({
          githubClient,
          pr,
          chatId,
          shareLink: record.shareLink,
          existingCommentId: record.shareLinkCommentId,
        });
        if (!res.posted) {
          throw new Error('Share link rejected by trusted Feishu/Lark domain validation');
        }
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.shareLinkPosted = true;
          if (res.commentId) cur.shareLinkCommentId = res.commentId;
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
      } catch (err) {
        const errMsg = `Share-link PR comment failed: ${formatSafeError(err, this.registry)}`;
        await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.status = 'creating';
          cur.lastError = errMsg;
          cur.updatedAt = new Date(this.now()).toISOString();
        });
        throw new Error(errMsg);
      }
    }

    // Final completion gate BEFORE Step 8: verify ALL required rule steps completed!
    const missingReasons: string[] = [];
    if ((rule.kickoffBotAppId || rule.setTopNotice) && !record.kickoffMessageId) {
      missingReasons.push('kickoff_message_missing');
    }
    if (record.kickoffMessageId && record.kickoffVerified !== true) {
      missingReasons.push('kickoff_not_verified');
    }
    if (rule.setTopNotice && !record.topNoticeSet) {
      missingReasons.push('top_notice_not_set');
    }
    if (rule.postShareLinkToPr && record.shareLink && !record.shareLinkPosted) {
      missingReasons.push('share_link_not_posted');
    }
    if (missingReasons.length > 0) {
      const reason = missingReasons.join(',');
      await this.stateStore.update(state => {
        const cur = state.prGroups[prKey]!;
        cur.status = 'creating';
        cur.lastError = reason;
        cur.updatedAt = new Date(this.now()).toISOString();
      });
      throw new Error(`PR group ${prKey} in ${chatId} incomplete (${reason}); remaining in creating state`);
    }

    // Step 8: Mark PR group active atomically ONLY after all required steps succeeded!
    record = await this.stateStore.update(state => {
      const cur = state.prGroups[prKey]!;
      cur.status = 'active';
      cur.lastHeadSha = pr.headSha;
      cur.updatedAt = new Date(this.now()).toISOString();
      delete cur.lastError;
      delete cur.createAttempt;
      return { ...cur };
    });

    return { record, reusedExisting, warnings };
  }

  async sendFollowUpUpdate(opts: {
    creatorLarkAppId: string;
    chatId: string;
    dedupSeed: string;
    content: string;
  }): Promise<{ messageId: string; replayed: boolean }> {
    const requestId = makeDeterministicRequestId(opts.dedupSeed);
    return this.sendGroupMessage({
      creatorLarkAppId: opts.creatorLarkAppId,
      chatId: opts.chatId,
      requestId,
      content: opts.content,
    });
  }
}
