import { createHmac, timingSafeEqual } from 'node:crypto';
import type http from 'node:http';
import type { PullRequestInfo } from '../types.ts';
import { MAX_WEBHOOK_BODY_BYTES } from '../types.ts';
import { isWebhookSecretAcceptable, normalizeRepoKey } from '../config/schema.ts';
import { computeIsFork } from '../security/sanitize.ts';
import { verifyDaemonIpcHeaders } from '../host/discovery.ts';

const SIG_HEADER_RE = /^sha256=([0-9a-f]{64})$/;
const SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;
const DELIVERY_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

export const MAX_CONTROL_BODY_BYTES = 65_536;

export class RequestBodyError extends Error {
  readonly status: 400 | 408 | 413;
  constructor(status: 400 | 408 | 413, message: string) {
    super(message);
    this.name = 'RequestBodyError';
    this.status = status;
  }
}

export function singleHeader(
  headers: http.IncomingHttpHeaders,
  name: string,
): string | null {
  const val = headers[name.toLowerCase()];
  if (typeof val !== 'string') return null;
  return val.trim();
}

export function isLoopbackRemoteAddress(addr: string | undefined): boolean {
  if (!addr) return false;
  return addr === '127.0.0.1' || addr === '::ffff:127.0.0.1' || addr === '::1';
}

export function isAllowedLoopbackHost(
  hostHeader: string | undefined,
  boundPort: number,
): boolean {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  const normalized = hostHeader.trim().toLowerCase();
  return (
    normalized === `127.0.0.1:${boundPort}` ||
    normalized === `localhost:${boundPort}` ||
    normalized === `[::1]:${boundPort}`
  );
}

/**
 * Reads an HTTP request body strictly bounded to `maxBytes` (checking both
 * Content-Length upfront and cumulative streaming chunk bytes to defeat
 * chunked Transfer-Encoding DoS and slowloris attacks).
 */
export function readRawBodyBounded(
  req: http.IncomingMessage,
  opts: { maxBytes: number; timeoutMs: number },
): Promise<Buffer> {
  const contentLenRaw = req.headers['content-length'];
  if (contentLenRaw !== undefined) {
    const raw = Array.isArray(contentLenRaw) ? contentLenRaw[0] : contentLenRaw;
    if (raw !== undefined) {
      if (!/^\d+$/.test(raw.trim())) {
        return Promise.reject(new RequestBodyError(400, 'Invalid Content-Length header'));
      }
      const declared = Number.parseInt(raw.trim(), 10);
      if (declared > opts.maxBytes) {
        req.resume();
        return Promise.reject(
          new RequestBodyError(413, `Payload exceeds maximum ${opts.maxBytes} bytes`),
        );
      }
    }
  }

  return new Promise<Buffer>((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(new RequestBodyError(408, 'Request body read timed out'));
    }, opts.timeoutMs);

    const finish = (err: Error | null, buf?: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolvePromise(buf!);
    };

    req.on('data', (chunk: Buffer | string) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > opts.maxBytes) {
        req.pause();
        req.destroy();
        finish(new RequestBodyError(413, `Payload exceeds maximum ${opts.maxBytes} bytes`));
        return;
      }
      chunks.push(buf);
    });

    req.on('error', err => finish(err));
    req.on('aborted', () => finish(new RequestBodyError(400, 'Request aborted')));
    req.on('end', () => {
      finish(null, chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, total));
    });
  });
}

/**
 * Verifies GitHub X-Hub-Signature-256 against exact raw body bytes using
 * crypto.timingSafeEqual BEFORE JSON.parse.
 * Rejects SHA-1 headers, duplicate header arrays, uppercase/malformed hex,
 * and secrets shorter than 32 bytes.
 */
export function verifyGitHubWebhookSignature(
  rawBody: Buffer,
  signatureHeader: string | string[] | undefined,
  secret: string,
): boolean {
  if (!isWebhookSecretAcceptable(secret)) return false;
  if (typeof signatureHeader !== 'string') return false;
  const match = SIG_HEADER_RE.exec(signatureHeader.trim());
  if (!match) return false;

  const providedHex = match[1]!;
  const providedBuf = Buffer.from(providedHex, 'hex');
  const expectedBuf = createHmac('sha256', secret.trim()).update(rawBody).digest();
  if (providedBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(providedBuf, expectedBuf);
}

export interface ParsedWebhookEvent {
  deliveryId: string;
  event: 'ping' | 'pull_request';
  action?: string;
  repo?: string;
  pr?: PullRequestInfo;
}

export interface WebhookValidationResult {
  status: number;
  ok: boolean;
  reason?: string;
  duplicate?: boolean;
  parsed?: ParsedWebhookEvent;
}

export type DeliveryAcquireStatus = 'acquired' | 'duplicate' | 'overloaded';

/**
 * Bounded in-memory LRU + TTL + bounded/expiring in-flight delivery deduplicator.
 * Never records deliveries prior to signature verification and repo allowlist check.
 */
export class DeliveryDedupCache {
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly maxInFlight: number;
  private readonly inFlightTimeoutMs: number;
  private readonly entries = new Map<string, number>();
  private readonly inFlight = new Map<string, number>();
  private readonly now: () => number;

  constructor(opts?: {
    maxEntries?: number;
    ttlMs?: number;
    maxInFlight?: number;
    inFlightTimeoutMs?: number;
    now?: () => number;
  }) {
    this.maxEntries = Math.max(1, opts?.maxEntries ?? 5_000);
    this.ttlMs = Math.max(1_000, opts?.ttlMs ?? 72 * 60 * 60 * 1000);
    this.maxInFlight = Math.max(1, opts?.maxInFlight ?? Math.min(256, this.maxEntries));
    this.inFlightTimeoutMs = Math.max(1_000, opts?.inFlightTimeoutMs ?? 5 * 60 * 1000);
    this.now = opts?.now ?? (() => Date.now());
  }

  hydrate(persisted: Record<string, string>): void {
    const nowMs = this.now();
    for (const [id, ts] of Object.entries(persisted)) {
      const parsed = Date.parse(ts);
      if (!Number.isNaN(parsed) && nowMs - parsed <= this.ttlMs) {
        this.entries.set(id, parsed + this.ttlMs);
      }
    }
    this.prune();
  }

  private prune(): void {
    const nowMs = this.now();
    for (const [k, exp] of this.entries.entries()) {
      if (exp <= nowMs) this.entries.delete(k);
    }
    for (const [k, exp] of this.inFlight.entries()) {
      if (exp <= nowMs) this.inFlight.delete(k);
    }
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) break;
      this.entries.delete(oldest);
    }
  }

  tryAcquire(deliveryId: string): DeliveryAcquireStatus {
    this.prune();
    if (this.inFlight.has(deliveryId) || this.entries.has(deliveryId)) {
      return 'duplicate';
    }
    if (this.inFlight.size >= this.maxInFlight) {
      return 'overloaded';
    }
    this.inFlight.set(deliveryId, this.now() + this.inFlightTimeoutMs);
    return 'acquired';
  }

  commit(deliveryId: string): void {
    this.inFlight.delete(deliveryId);
    this.entries.set(deliveryId, this.now() + this.ttlMs);
    this.prune();
  }

  abort(deliveryId: string): void {
    this.inFlight.delete(deliveryId);
  }

  size(): number {
    this.prune();
    return this.entries.size;
  }

  inFlightSize(): number {
    this.prune();
    return this.inFlight.size;
  }
}

/**
 * Verifies the host-injected `Authorization: Bearer <BOTMUX_PLUGIN_WEBHOOK_TOKEN>`
 * header mandated by deepcoldy/botmux#3830 when running behind Botmux's webhook gateway.
 */
export function verifyWebhookHostToken(
  headers: http.IncomingHttpHeaders,
  expectedToken: string,
): boolean {
  const authHeader = singleHeader(headers, 'authorization');
  if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
    return false;
  }
  const provided = authHeader.slice(7).trim();
  if (!provided) return false;
  return safeTokenEqual(provided, expectedToken);
}

/**
 * Validates raw webhook headers & body in strict security order:
 * 1. Secret >= 32 bytes & webhook enabled
 * 2. Exact raw-bytes HMAC-SHA256 verification BEFORE JSON.parse
 * 3. JSON parse & schema extraction
 * 4. Repo allowlist check BEFORE X-GitHub-Delivery dedup recording
 */
export function verifyAndParseWebhookPayload(opts: {
  headers: http.IncomingHttpHeaders;
  rawBody: Buffer;
  webhookEnabled: boolean;
  webhookSecret: string | undefined;
  allowedRepoKeys: ReadonlySet<string>;
  dedupCache: DeliveryDedupCache;
}): WebhookValidationResult {
  if (!opts.webhookEnabled || !isWebhookSecretAcceptable(opts.webhookSecret)) {
    return { status: 503, ok: false, reason: 'webhook_not_configured' };
  }

  if (opts.rawBody.length === 0 || opts.rawBody.length > MAX_WEBHOOK_BODY_BYTES) {
    return { status: 413, ok: false, reason: 'invalid_body_size' };
  }

  // Reject cross-origin browser requests carrying Origin header
  if (opts.headers.origin) {
    return { status: 403, ok: false, reason: 'origin_header_forbidden' };
  }

  const contentType = singleHeader(opts.headers, 'content-type') ?? '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    return { status: 415, ok: false, reason: 'unsupported_media_type' };
  }

  // CRITICAL: Verify HMAC over raw bytes BEFORE JSON.parse!
  if (
    !verifyGitHubWebhookSignature(
      opts.rawBody,
      opts.headers['x-hub-signature-256'],
      opts.webhookSecret,
    )
  ) {
    return { status: 401, ok: false, reason: 'invalid_signature' };
  }

  const eventHeader = singleHeader(opts.headers, 'x-github-event');
  if (!eventHeader) {
    return { status: 400, ok: false, reason: 'missing_github_event' };
  }

  const deliveryId = singleHeader(opts.headers, 'x-github-delivery');
  if (
    !deliveryId ||
    !DELIVERY_ID_RE.test(deliveryId) ||
    deliveryId === '__proto__' ||
    deliveryId === 'constructor' ||
    deliveryId === 'prototype'
  ) {
    return { status: 400, ok: false, reason: 'missing_or_invalid_delivery_id' };
  }

  let payload: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(opts.rawBody.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { status: 400, ok: false, reason: 'invalid_json_object' };
    }
    payload = parsed as Record<string, unknown>;
  } catch {
    return { status: 400, ok: false, reason: 'invalid_json' };
  }

  if (eventHeader === 'ping') {
    const repoObj = payload.repository as { full_name?: unknown } | undefined;
    const repoName = typeof repoObj?.full_name === 'string' ? repoObj.full_name.trim() : undefined;
    if (repoName && !opts.allowedRepoKeys.has(normalizeRepoKey(repoName))) {
      return { status: 403, ok: false, reason: 'repo_not_allowlisted' };
    }
    return {
      status: 200,
      ok: true,
      parsed: { deliveryId, event: 'ping', ...(repoName ? { repo: repoName } : {}) },
    };
  }

  if (eventHeader !== 'pull_request') {
    return { status: 204, ok: true, reason: 'ignored_event' };
  }

  const repoObj = payload.repository as { full_name?: unknown } | undefined;
  const repoFullName = typeof repoObj?.full_name === 'string' ? repoObj.full_name.trim() : '';
  if (!repoFullName || !opts.allowedRepoKeys.has(normalizeRepoKey(repoFullName))) {
    // Reject non-allowlisted repo BEFORE recording deliveryId (prevents dedup cache poisoning).
    return { status: 403, ok: false, reason: 'repo_not_allowlisted' };
  }

  const action = typeof payload.action === 'string' ? payload.action.trim() : '';
  const supportedActions = new Set([
    'opened',
    'ready_for_review',
    'synchronize',
    'closed',
    'reopened',
  ]);
  if (!supportedActions.has(action)) {
    return { status: 204, ok: true, reason: 'ignored_action' };
  }

  const prRaw = payload.pull_request as Record<string, unknown> | undefined;
  if (!prRaw || typeof prRaw !== 'object') {
    return { status: 400, ok: false, reason: 'missing_pull_request' };
  }

  const number = prRaw.number;
  if (typeof number !== 'number' || !Number.isInteger(number) || number < 1) {
    return { status: 400, ok: false, reason: 'invalid_pr_number' };
  }

  const head = prRaw.head as {
    ref?: unknown;
    sha?: unknown;
    repo?: { full_name?: unknown; fork?: unknown } | null;
  } | null;
  const base = prRaw.base as {
    ref?: unknown;
    repo?: { full_name?: unknown } | null;
  } | null;
  const headSha = typeof head?.sha === 'string' ? head.sha.trim() : '';
  if (!SHA_RE.test(headSha)) {
    return { status: 400, ok: false, reason: 'invalid_head_sha' };
  }

  const headRepoFullName =
    typeof head?.repo?.full_name === 'string' && head.repo.full_name.trim()
      ? head.repo.full_name.trim()
      : null;
  const baseRepoName =
    typeof base?.repo?.full_name === 'string' && base.repo.full_name.trim()
      ? base.repo.full_name.trim()
      : repoFullName;

  const isFork = computeIsFork(baseRepoName, {
    full_name: headRepoFullName,
    fork: head?.repo?.fork === true,
  });

  const labels = Array.isArray(prRaw.labels)
    ? (prRaw.labels as Array<{ name?: unknown }>)
        .map(l => (typeof l?.name === 'string' ? l.name.trim() : ''))
        .filter(Boolean)
    : [];

  const user = prRaw.user as { login?: unknown } | null | undefined;
  const pr: PullRequestInfo = {
    repo: repoFullName,
    number,
    title: typeof prRaw.title === 'string' ? prRaw.title : '',
    body: typeof prRaw.body === 'string' ? prRaw.body : '',
    state: prRaw.state === 'closed' ? 'closed' : 'open',
    draft: prRaw.draft === true,
    merged: prRaw.merged === true || Boolean(prRaw.merged_at),
    htmlUrl: typeof prRaw.html_url === 'string' ? prRaw.html_url : '',
    author: typeof user?.login === 'string' ? user.login : 'unknown',
    baseBranch: typeof base?.ref === 'string' ? base.ref : '',
    headBranch: typeof head?.ref === 'string' ? head.ref : '',
    headSha,
    headRepoFullName,
    labels,
    isFork,
    maintainerCanModify:
      typeof prRaw.maintainer_can_modify === 'boolean' ? prRaw.maintainer_can_modify : null,
    createdAt: typeof prRaw.created_at === 'string' ? prRaw.created_at : '',
    updatedAt: typeof prRaw.updated_at === 'string' ? prRaw.updated_at : '',
  };

  // Deduplicate deliveryId ONLY after signature, schema, and repo allowlist checks pass!
  const acquired = opts.dedupCache.tryAcquire(deliveryId);
  if (acquired === 'overloaded') {
    return {
      status: 503,
      ok: false,
      reason: 'webhook_inflight_limit_exceeded',
    };
  }
  if (acquired === 'duplicate') {
    return {
      status: 200,
      ok: true,
      duplicate: true,
      parsed: { deliveryId, event: 'pull_request', action, repo: repoFullName, pr },
    };
  }

  return {
    status: 202,
    ok: true,
    duplicate: false,
    parsed: { deliveryId, event: 'pull_request', action, repo: repoFullName, pr },
  };
}

function safeTokenEqual(provided: string, expected: string): boolean {
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Authorizes local 127.0.0.1 control API calls (/api/status, /api/reload, /api/sync,
 * /api/open-pr, /api/test-auth) against CSRF, DNS rebinding, and untrusted local callers.
 */
export function authorizeControlRequest(opts: {
  req: http.IncomingMessage;
  boundPort: number;
  controlToken: string;
  dashboardSecret?: string | null;
  hostBearerTokens?: string[];
  seenNonces: Map<string, number>;
}): { ok: true } | { ok: false; status: 401 | 403 | 415; reason: string } {
  const { req, boundPort } = opts;

  if (!isLoopbackRemoteAddress(req.socket?.remoteAddress)) {
    return { ok: false, status: 403, reason: 'remote_not_loopback' };
  }

  if (!isAllowedLoopbackHost(req.headers.host, boundPort)) {
    return { ok: false, status: 403, reason: 'invalid_host_header' };
  }

  // Unconditionally reject browser cross-site / fetch metadata headers
  if (
    req.headers.origin ||
    req.headers.referer ||
    req.headers['sec-fetch-mode'] ||
    req.headers['sec-fetch-site']
  ) {
    return { ok: false, status: 403, reason: 'browser_csrf_headers_rejected' };
  }

  const method = (req.method ?? 'GET').toUpperCase();
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
    const ct = singleHeader(req.headers, 'content-type') ?? '';
    if (!ct.toLowerCase().startsWith('application/json')) {
      return { ok: false, status: 415, reason: 'content_type_must_be_json' };
    }
    const ctrlHeader = singleHeader(req.headers, 'x-botmux-plugin-control');
    if (ctrlHeader !== '1') {
      return { ok: false, status: 403, reason: 'missing_control_header' };
    }
  }

  // Credential check: (1) X-Botmux-Github-Token or Authorization: Bearer matching controlToken or host token
  const pluginToken = singleHeader(req.headers, 'x-botmux-github-token');
  if (pluginToken && safeTokenEqual(pluginToken, opts.controlToken)) {
    return { ok: true };
  }

  const authHeader = singleHeader(req.headers, 'authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer && safeTokenEqual(bearer, opts.controlToken)) {
      return { ok: true };
    }
    for (const hostToken of opts.hostBearerTokens ?? []) {
      if (hostToken && bearer && safeTokenEqual(bearer, hostToken)) {
        return { ok: true };
      }
    }
  }

  // (2) Botmux daemon HMAC headers signed with ~/.botmux/.dashboard-secret
  if (opts.dashboardSecret) {
    const urlPath = req.url ?? '/';
    if (
      verifyDaemonIpcHeaders(
        req.headers,
        opts.dashboardSecret,
        method,
        urlPath,
        boundPort,
        opts.seenNonces,
      )
    ) {
      return { ok: true };
    }
  }

  return { ok: false, status: 401, reason: 'unauthorized' };
}
