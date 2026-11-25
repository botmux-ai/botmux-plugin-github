import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import type {
  LarkBrand,
  PrGroupRecord,
  ProxyConfig,
  PullRequestInfo,
  RepoRule,
} from '../types.ts';
import { MAX_IPC_TEXT_BYTES } from '../types.ts';
import { loopbackRequest } from '../security/net.ts';
import { SecretRegistry, defaultSecretRegistry, formatSafeError } from '../security/redact.ts';
import { buildKickoffPrompt, renderSafeGroupName } from '../security/sanitize.ts';
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

export interface CliExecFn {
  (
    bin: string,
    args: string[],
    opts: { timeoutMs: number; env: Record<string, string | undefined> },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

export interface HostBridgeOptions {
  stateStore: StateStore;
  discovery?: DiscoveryOptions;
  proxy?: ProxyConfig;
  registry?: SecretRegistry;
  larkClient?: LarkOpenApiClient;
  cliExec?: CliExecFn;
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
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
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
        const exitCode =
          err && typeof (err as { code?: unknown }).code === 'number'
            ? ((err as { code: number }).code)
            : err
              ? 1
              : 0;
        resolvePromise({
          exitCode,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
        });
      },
    );
  });
}

function makeDeterministicRequestId(seed: string): string {
  const hash = createHash('sha256').update(seed).digest('hex').slice(0, 32);
  return `gh_${hash}`;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Checks whether an existing Feishu group name matches the exact expected group
 * name or starts with the trusted canonical prefix `[owner/repo#N]` or
 * `PR #N owner/repo`. Strictly anchored to the start so untrusted PR titles
 * mentioning other PR numbers (e.g. "see owner/repo#51") can NEVER hijack
 * deduplication for future PRs!
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
  // Strictly anchored to trusted prefix: "[owner/repo#N]" or "PR #N owner/repo"
  const bracketPrefixRe = new RegExp(`^\\[${repoEsc}#${prNumber}\\](?=$|[\\s\\-:])`, 'i');
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
    const chats = (resp.json as { chats?: unknown }).chats;
    if (!Array.isArray(chats)) {
      return { groups: [], ipcPort: daemon.ipcPort, secret };
    }
    const groups: DaemonGroupItem[] = chats
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
    const line1 = lines[0] ?? '';
    const line2 = lines[1] ?? '';

    let chatId = CHAT_ID_RE.test(line1) ? line1 : '';
    let kickoffMessageId: string | null = null;
    let kickoffError: string | null = null;

    if (line2) {
      try {
        const parsed = JSON.parse(line2) as {
          chatId?: unknown;
          kickoffMessageId?: unknown;
          kickoffError?: unknown;
        };
        if (!chatId && typeof parsed.chatId === 'string' && CHAT_ID_RE.test(parsed.chatId)) {
          chatId = parsed.chatId;
        }
        if (typeof parsed.kickoffMessageId === 'string' && MESSAGE_ID_RE.test(parsed.kickoffMessageId)) {
          kickoffMessageId = parsed.kickoffMessageId;
        }
        if (typeof parsed.kickoffError === 'string') {
          kickoffError = parsed.kickoffError;
        }
      } catch {
        // Ignore malformed line 2 if chatId already captured from line 1
      }
    }

    // Even if exitCode !== 0, if chatId was flushed on stdout line 1, return it so we NEVER create a duplicate!
    if (!chatId) {
      throw new Error(
        `botmux create-group CLI failed (exit ${result.exitCode}): ${this.registry.redactString(result.stderr.slice(0, 300))}`,
      );
    }

    return { chatId, kickoffMessageId, kickoffError };
  }

  private async postShareLinkIdempotently(opts: {
    githubClient: GitHubClient;
    pr: PullRequestInfo;
    chatId: string;
    shareLink: string;
  }): Promise<boolean> {
    const normalizedLink = normalizeTrustedLarkShareLink(opts.shareLink);
    if (!normalizedLink) {
      return false;
    }
    const [owner, repo] = opts.pr.repo.split('/');
    if (!owner || !repo) return false;

    const marker = `<!-- botmux-plugin-github:share-link:${opts.chatId} -->`;
    const comments = await opts.githubClient.listIssueComments(owner, repo, opts.pr.number);
    if (comments.some(c => c.body.includes(marker))) {
      return true; // Already posted (even if state.json was lost)
    }

    const commentBody = buildShareLinkPrComment(normalizedLink, opts.chatId);
    await opts.githubClient.createIssueComment(owner, repo, opts.pr.number, commentBody);
    return true;
  }

  /**
   * Executes the full crash-safe PR review group orchestration flow:
   * - Resumes cleanly from any persisted step without ever creating a duplicate group
   * - Queries creator daemon GET /api/groups before creating even if state was wiped
   * - Persists chatId immediately upon creation (including partial 502 responses)
   * - Handles dual-core kickoff + readback verification + dual-path top-notice + idempotent PR comment
   */
  async ensurePrReviewGroup(opts: {
    rule: RepoRule;
    pr: PullRequestInfo;
    githubClient: GitHubClient;
  }): Promise<GroupOrchestrationResult> {
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
        // Keep existing chatId / kickoff / topNotice flags across crash resume!
        existing.updatedAt = nowIso;
        existing.lastHeadSha = pr.headSha;
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
        }
      }
    }

    // Step 3: Create group ONLY if chatId is still unknown
    if (!record.chatId) {
      const larkAppIds = [rule.creatorBotAppId];
      for (const id of validMemberBotAppIds) {
        if (!larkAppIds.includes(id)) larkAppIds.push(id);
      }
      if (rule.kickoffBotAppId && !larkAppIds.includes(rule.kickoffBotAppId)) {
        larkAppIds.push(rule.kickoffBotAppId);
      }

      if (canUseDaemonIpc && creatorDaemon && dashboardSecret) {
        // Resolve human invitees & owner transfer from creator daemon's resolvedAllowedUsers
        const userOpenIds = creatorDaemon.resolvedAllowedUsers.filter(u => u.startsWith('ou_'));
        const ownerUnionIds = creatorDaemon.resolvedAllowedUsers.filter(u => u.startsWith('on_'));

        const createBody: Record<string, unknown> = {
          name: groupName,
          larkAppIds,
          chatMode: rule.chatMode,
          ...(rule.bindWorkingDir ? { bindWorkingDir: rule.bindWorkingDir } : {}),
          ...(userOpenIds.length > 0 ? { userOpenIds } : {}),
          ...(ownerUnionIds.length > 0 ? { ownerUnionIds } : {}),
          ...(userOpenIds[0]
            ? { transferOwnerTo: userOpenIds[0] }
            : ownerUnionIds[0]
              ? { transferOwnerUnionId: ownerUnionIds[0] }
              : {}),
          ...(larkAppIds.length >= 2 ? { botCollaboration: true } : {}),
          // Upcoming core PR fields (silently ignored on current core; handled natively on new core)
          ...(rule.kickoffBotAppId
            ? {
                kickoffBotLarkAppId: rule.kickoffBotAppId,
                kickoffPrompt: kickoffPromptBase,
              }
            : {}),
          ownerNotice: false,
        };

        const resp = await this.daemonRequest({
          ipcPort: creatorDaemon.ipcPort,
          secret: dashboardSecret,
          method: 'POST',
          path: '/api/groups/create',
          body: createBody,
          timeoutMs: 35_000,
        });

        const body = (resp.json && typeof resp.json === 'object'
          ? resp.json
          : {}) as DaemonCreateGroupResponse;

        // CRITICAL: Immediately persist chatId even on HTTP 502 partial failure so retries NEVER double-create!
        if (typeof body.chatId === 'string' && CHAT_ID_RE.test(body.chatId)) {
          record = await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.chatId = body.chatId;
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
          throw new Error(
            `POST /api/groups/create failed (${resp.status}): ${this.registry.redactString(body.error ?? resp.rawText.slice(0, 200))}`,
          );
        }
      } else {
        // Fallback when creator daemon IPC is unavailable: botmux create-group CLI
        const cliRes = await this.createGroupViaCliFallback({
          rule,
          groupName,
          kickoffPrompt: kickoffPromptBase,
        });
        record = await this.stateStore.update(state => {
          const cur = state.prGroups[prKey]!;
          cur.chatId = cliRes.chatId;
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
      // Crash-recovery check: see if kickoff was already posted before a prior crash!
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
          cur.updatedAt = new Date(this.now()).toISOString();
          return { ...cur };
        });
      }
    }

    // Step 5: Readback verification of kickoffMessageId confirming it matches current PR number
    if (record.kickoffMessageId && !record.kickoffVerified && canUseDaemonIpc && creatorDaemon && dashboardSecret) {
      const check = await this.verifyKickoffMessageReadback(
        chatId,
        record.kickoffMessageId,
        rule.repo,
        pr.number,
        creatorDaemon.ipcPort,
        dashboardSecret,
      );
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
          kind: 'kickoff_readback_mismatch',
          repo: rule.repo,
          prNumber: pr.number,
          chatId,
          message: `Kickoff message ${record.kickoffMessageId} readback check failed: ${reason}`,
        });

        // Definite mismatch or deleted kickoff message: NEVER pin it as top notice or mark active!
        if (
          reason === 'kickoff_message_pr_mismatch' ||
          reason === 'kickoff_message_deleted' ||
          reason === 'kickoff_message_chat_mismatch'
        ) {
          await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.kickoffMessageId = null;
            cur.kickoffVerified = false;
            cur.lastError = reason;
            cur.updatedAt = new Date(this.now()).toISOString();
          });
          throw new Error(
            `Kickoff message readback rejected for ${prKey} in ${chatId}: ${reason}`,
          );
        }
        warnings.push(`Kickoff readback verification warning: ${reason}`);
      }
    }

    // Step 6: Top-notice pinning (new core IPC -> direct Feishu/Lark Open Platform fallback)
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
        warnings.push(`Top notice warning: ${noticeRes.error ?? 'failed'}`);
        await this.stateStore.appendEvent({
          level: 'warn',
          kind: 'top_notice_failed',
          repo: rule.repo,
          prNumber: pr.number,
          chatId,
          message: `Failed to pin top notice: ${noticeRes.error ?? 'unknown'}`,
        });
      }
    }

    // Step 7: Optional idempotent PR share-link comment
    if (rule.postShareLinkToPr && record.shareLink && !record.shareLinkPosted) {
      try {
        const posted = await this.postShareLinkIdempotently({
          githubClient,
          pr,
          chatId,
          shareLink: record.shareLink,
        });
        if (posted) {
          record = await this.stateStore.update(state => {
            const cur = state.prGroups[prKey]!;
            cur.shareLinkPosted = true;
            cur.updatedAt = new Date(this.now()).toISOString();
            return { ...cur };
          });
        }
      } catch (err) {
        warnings.push(`Share-link PR comment failed: ${formatSafeError(err, this.registry)}`);
      }
    }

    // Step 8: Mark PR group active atomically
    record = await this.stateStore.update(state => {
      const cur = state.prGroups[prKey]!;
      cur.status = 'active';
      cur.lastHeadSha = pr.headSha;
      cur.updatedAt = new Date(this.now()).toISOString();
      delete cur.lastError;
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
