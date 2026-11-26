import { createHash } from 'node:crypto';
import type {
  AuthTestResult,
  GitHubAuthConfig,
  ProxyConfig,
  PullRequestInfo,
  RateLimitState,
} from '../types.ts';
import {
  parseProxyStateFailClosed,
  secureOutboundRequest,
  validateGitHubApiBaseUrl,
  type HttpResponseResult,
  type ProxyState,
} from '../security/net.ts';
import {
  SecretRegistry,
  defaultSecretRegistry,
  formatSafeError,
} from '../security/redact.ts';
import { computeIsFork } from '../security/sanitize.ts';
import { validateRepoSlug } from '../config/schema.ts';
import { GitHubAuthManager, type GhCliRunner } from './auth.ts';
import { RateLimitTracker } from './ratelimit.ts';

const MAX_ETAG_CACHE_ENTRIES = 400;
const VALID_ETAG_RE = /^[\x21-\x7E ]{1,256}$/;

interface ETagEntry {
  etag: string;
  body: string;
  link?: string;
  hasNonEmptyNextPage?: boolean;
  usedAt: number;
}

export class GitHubApiError extends Error {
  readonly status: number;
  readonly rateLimited: boolean;

  constructor(message: string, status: number, rateLimited = false) {
    super(message);
    this.name = 'GitHubApiError';
    this.status = status;
    this.rateLimited = rateLimited;
  }
}

export class GitHubRateLimitPausedError extends Error {
  readonly code = 'GITHUB_RATE_LIMIT_PAUSED';
  readonly reason: string;
  readonly until?: string;

  constructor(reason: string, until?: string) {
    super(`GitHub requests paused (${reason}${until ? ` until ${until}` : ''})`);
    this.name = 'GitHubRateLimitPausedError';
    this.reason = reason;
    this.until = until;
  }
}

interface RawGitHubPr {
  number?: unknown;
  title?: unknown;
  body?: unknown;
  state?: unknown;
  draft?: unknown;
  merged?: unknown;
  merged_at?: unknown;
  html_url?: unknown;
  user?: { login?: unknown } | null;
  base?: { ref?: unknown; repo?: { full_name?: unknown } | null } | null;
  head?: {
    ref?: unknown;
    sha?: unknown;
    repo?: { full_name?: unknown; fork?: unknown } | null;
  } | null;
  labels?: Array<{ name?: unknown }> | null;
  maintainer_can_modify?: unknown;
  created_at?: unknown;
  updated_at?: unknown;
}

export interface IssueComment {
  id: number;
  body: string;
  htmlUrl: string;
  userLogin: string;
}

function headerFirst(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string {
  const val = headers[name.toLowerCase()] ?? headers[name];
  if (Array.isArray(val)) return val[0] ?? '';
  return typeof val === 'string' ? val.trim() : '';
}

function parsePrObject(repo: string, raw: RawGitHubPr): PullRequestInfo | null {
  if (typeof raw.number !== 'number' || !Number.isInteger(raw.number) || raw.number < 1) {
    return null;
  }
  const headSha = typeof raw.head?.sha === 'string' ? raw.head.sha.trim() : '';
  if (!headSha) return null;

  const baseRepoName =
    typeof raw.base?.repo?.full_name === 'string' && raw.base.repo.full_name.trim()
      ? raw.base.repo.full_name.trim()
      : repo;
  const headRepoFullName =
    typeof raw.head?.repo?.full_name === 'string' && raw.head.repo.full_name.trim()
      ? raw.head.repo.full_name.trim()
      : null;

  const isFork = computeIsFork(baseRepoName, {
    full_name: headRepoFullName,
    fork: raw.head?.repo?.fork === true,
  });

  const labels = Array.isArray(raw.labels)
    ? raw.labels
        .map(l => (typeof l?.name === 'string' ? l.name.trim() : ''))
        .filter(Boolean)
    : [];

  return {
    repo,
    number: raw.number,
    title: typeof raw.title === 'string' ? raw.title : '',
    body: typeof raw.body === 'string' ? raw.body : '',
    state: raw.state === 'closed' ? 'closed' : 'open',
    draft: raw.draft === true,
    merged: raw.merged === true || Boolean(raw.merged_at),
    htmlUrl: typeof raw.html_url === 'string' ? raw.html_url : '',
    author: typeof raw.user?.login === 'string' ? raw.user.login : 'unknown',
    baseBranch: typeof raw.base?.ref === 'string' ? raw.base.ref : '',
    headBranch: typeof raw.head?.ref === 'string' ? raw.head.ref : '',
    headSha,
    headRepoFullName,
    labels,
    isFork,
    maintainerCanModify:
      typeof raw.maintainer_can_modify === 'boolean' ? raw.maintainer_can_modify : null,
    createdAt: typeof raw.created_at === 'string' ? raw.created_at : '',
    updatedAt: typeof raw.updated_at === 'string' ? raw.updated_at : '',
  };
}

function hasNextPageLink(linkHeader: string): boolean {
  return /<[^>]+>;\s*rel="next"/i.test(linkHeader);
}

export class GitHubClient {
  readonly apiBaseUrl: URL;
  readonly webOrigin: string;
  readonly allowPrivateIntranet: boolean;
  readonly proxyState: ProxyState;
  readonly rateLimits: RateLimitTracker;

  private readonly authConfig: GitHubAuthConfig;
  private readonly authManager: GitHubAuthManager;
  private readonly registry: SecretRegistry;
  private readonly allowInsecureLocalForTests: boolean;
  private readonly testCa?: string | Buffer;
  private readonly etagCache = new Map<string, ETagEntry>();
  private readonly now: () => number;

  constructor(opts: {
    auth: GitHubAuthConfig;
    proxy?: ProxyConfig;
    initialRateLimits?: RateLimitState;
    registry?: SecretRegistry;
    ghRunner?: GhCliRunner;
    allowInsecureLocalForTests?: boolean;
    testCa?: string | Buffer;
    now?: () => number;
  }) {
    this.registry = opts.registry ?? defaultSecretRegistry;
    this.authConfig = opts.auth;
    this.allowInsecureLocalForTests = opts.allowInsecureLocalForTests === true;
    this.testCa = opts.testCa;
    this.now = opts.now ?? (() => Date.now());

    const validated = validateGitHubApiBaseUrl(opts.auth.apiBaseUrl, {
      allowInsecureLocalForTests: this.allowInsecureLocalForTests,
    });
    this.apiBaseUrl = validated.apiBaseUrl;
    this.webOrigin = validated.webOrigin;
    this.allowPrivateIntranet = validated.allowPrivateIntranet;

    this.proxyState = parseProxyStateFailClosed(
      opts.proxy?.url,
      { username: opts.proxy?.username, password: opts.proxy?.password },
      this.registry,
    );

    this.authManager = new GitHubAuthManager({
      auth: opts.auth,
      proxy: this.proxyState,
      registry: this.registry,
      ghRunner: opts.ghRunner,
      allowInsecureLocalForTests: this.allowInsecureLocalForTests,
      now: this.now,
    });

    this.rateLimits = new RateLimitTracker({
      initial: opts.initialRateLimits,
      now: this.now,
    });
  }

  private buildUrl(pathWithQuery: string): URL {
    const basePath = this.apiBaseUrl.pathname.replace(/\/+$/, '');
    const rel = pathWithQuery.startsWith('/') ? pathWithQuery : `/${pathWithQuery}`;
    return new URL(`${this.apiBaseUrl.origin}${basePath}${rel}`);
  }

  private makeEtagKey(principalFingerprint: string, pathWithQuery: string): string {
    return createHash('sha256')
      .update(`${this.apiBaseUrl.origin}${this.apiBaseUrl.pathname}\0${principalFingerprint}\0${pathWithQuery}`)
      .digest('hex');
  }

  private putEtagEntry(key: string, entry: ETagEntry): void {
    if (!VALID_ETAG_RE.test(entry.etag)) return;
    if (this.etagCache.size >= MAX_ETAG_CACHE_ENTRIES && !this.etagCache.has(key)) {
      let oldestKey: string | undefined;
      let oldestUsed = Infinity;
      for (const [k, v] of this.etagCache.entries()) {
        if (v.usedAt < oldestUsed) {
          oldestUsed = v.usedAt;
          oldestKey = k;
        }
      }
      if (oldestKey) this.etagCache.delete(oldestKey);
    }
    this.etagCache.set(key, entry);
  }

  clearEtagCache(): void {
    this.etagCache.clear();
  }

  /**
   * Executes an authenticated GitHub REST request with fail-closed proxy,
   * rate-limit header tracking, secondary rate-limit backoff, single 401
   * refresh retry, and secret scrubbing on all errors.
   */
  async request(opts: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    path: string;
    body?: unknown;
    etag?: string;
    resource?: 'core' | 'search';
    priority?: 'core' | 'non_core';
    bypassPauseCheck?: boolean;
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<{
    res: HttpResponseResult;
    method: 'pat' | 'github_app' | 'gh_cli';
    principalFingerprint: string;
  }> {
    if (opts.signal?.aborted) {
      const abortErr = new Error('GitHub request aborted');
      abortErr.name = 'AbortError';
      throw abortErr;
    }

    // Fail closed immediately on invalid proxy config before doing anything.
    if (this.proxyState.kind === 'invalid') {
      throw this.proxyState.error;
    }

    if (!opts.bypassPauseCheck) {
      const check = this.rateLimits.shouldPause({
        resource: opts.resource ?? 'core',
        priority: opts.priority ?? 'core',
      });
      if (check.paused) {
        throw new GitHubRateLimitPausedError(check.reason ?? 'rate_limited', check.until);
      }
    }

    const url = this.buildUrl(opts.path);
    const bodyBuf =
      opts.body !== undefined ? Buffer.from(JSON.stringify(opts.body), 'utf8') : undefined;

    let refusedToken: string | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (opts.signal?.aborted) {
        const abortErr = new Error('GitHub request aborted');
        abortErr.name = 'AbortError';
        throw abortErr;
      }

      const resolved = await this.authManager.getToken({
        forceRefresh: attempt > 0,
        refusedToken,
      });

      if (opts.signal?.aborted) {
        const abortErr = new Error('GitHub request aborted');
        abortErr.name = 'AbortError';
        throw abortErr;
      }

      const headers: Record<string, string> = {
        Authorization: `Bearer ${resolved.token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'botmux-plugin-github',
      };
      if (bodyBuf !== undefined) {
        headers['Content-Type'] = 'application/json';
      }
      if (opts.etag && VALID_ETAG_RE.test(opts.etag)) {
        headers['If-None-Match'] = opts.etag;
      }

      let res: HttpResponseResult;
      try {
        res = await secureOutboundRequest({
          url,
          method: opts.method,
          headers,
          body: bodyBuf,
          proxy: this.proxyState,
          allowPrivateIntranet: this.allowPrivateIntranet,
          allowedOrigin: this.apiBaseUrl.origin,
          allowedPathPrefix: this.apiBaseUrl.pathname.replace(/\/+$/, '') || '/',
          skipIpBlockCheck: this.allowInsecureLocalForTests,
          timeoutMs: opts.timeoutMs ?? 30_000,
          maxResponseBytes: 8 * 1024 * 1024,
          signal: opts.signal,
          ...(this.testCa ? { ca: this.testCa } : {}),
        });
      } catch (err) {
        if (err instanceof Error && (err.name === 'AbortError' || (err as { code?: string }).code === 'PROXY_CONFIG_INVALID')) {
          throw err;
        }
        throw new Error(formatSafeError(err, this.registry));
      }

      this.rateLimits.noteHeaders(res.headers);

      // Single 401 token refresh retry for renewable auth modes (github_app, gh_cli).
      if (res.status === 401 && attempt === 0 && resolved.method !== 'pat') {
        refusedToken = resolved.token;
        continue;
      }

      if (res.status === 401) {
        // Never echo 401 body verbatim.
        throw new GitHubApiError('GitHub authentication failed (401 Unauthorized)', 401, false);
      }

      if (res.status >= 400) {
        let apiMsg = '';
        try {
          const parsed = JSON.parse(res.body.toString('utf8')) as { message?: string };
          apiMsg = typeof parsed.message === 'string' ? parsed.message : '';
        } catch {
          apiMsg = res.body.toString('utf8').slice(0, 200);
        }
        const safeMsg = this.registry.redactString(apiMsg || `HTTP ${res.status}`);
        const rateLimited = this.rateLimits.notePause(res.status, res.headers, safeMsg);
        throw new GitHubApiError(
          `GitHub ${opts.method} ${opts.path}: ${res.status} ${safeMsg}`,
          res.status,
          rateLimited,
        );
      }

      return {
        res,
        method: resolved.method,
        principalFingerprint: resolved.principalFingerprint,
      };
    }

    throw new GitHubApiError('GitHub authentication failed after token refresh', 401, false);
  }

  /**
   * Lists open pull requests for a repository with per-page ETag / If-None-Match
   * conditional polling (304 Not Modified consumes zero rate limit quota).
   * When a repository spans >1 page (>100 open PRs), page-1 304 does NOT blindly
   * skip page 2+: every page is validated with its own conditional ETag so closing
   * or updating a PR on page 2+ is never masked by an unchanged page 1.
   */
  async listOpenPullRequests(
    owner: string,
    repo: string,
    opts?: {
      persistedEtag?: string;
      persistedEtagKey?: string;
      previousPageCount?: number;
      bypassEtag?: boolean;
      maxPages?: number;
      priority?: 'core' | 'non_core';
      signal?: AbortSignal;
    },
  ): Promise<{
    notModified: boolean;
    pulls: PullRequestInfo[];
    etag?: string;
    etagKey: string;
    truncated: boolean;
    pageCount: number;
  }> {
    const repoSlug = `${owner}/${repo}`;
    const makePagePath = (page: number) =>
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls?state=open&sort=updated&direction=desc&per_page=100&page=${page}`;
    const page1Path = makePagePath(1);
    const maxPages = Math.max(1, Math.min(opts?.maxPages ?? 10, 20));

    const tokenInfo = await this.authManager.getToken();
    const etagKey = this.makeEtagKey(tokenInfo.principalFingerprint, page1Path);

    const cachedPage1 = this.etagCache.get(etagKey);
    const knownMultiPage =
      (opts?.previousPageCount !== undefined && opts.previousPageCount > 1) ||
      cachedPage1?.hasNonEmptyNextPage === true;

    // If multi-page across cold restart (no cached page-1 body in memory), bypass ETag once
    // to repopulate full multi-page cache instead of blindly trusting page-1 304.
    const effectiveBypassEtag =
      opts?.bypassEtag === true || (knownMultiPage && !cachedPage1);

    let sendPage1Etag: string | undefined;
    if (!effectiveBypassEtag) {
      if (cachedPage1) {
        sendPage1Etag = cachedPage1.etag;
      } else if (
        opts?.persistedEtag &&
        opts.persistedEtagKey === etagKey &&
        VALID_ETAG_RE.test(opts.persistedEtag)
      ) {
        sendPage1Etag = opts.persistedEtag;
      }
    }

    const page1Resp = await this.request({
      method: 'GET',
      path: page1Path,
      etag: sendPage1Etag,
      resource: 'core',
      priority: opts?.priority ?? 'core',
      signal: opts?.signal,
    });

    let anyPageModified = page1Resp.res.status !== 304;
    let page1Etag: string | undefined;
    let page1RawText: string;
    let page1Link: string;

    if (page1Resp.res.status === 304) {
      const rotated = headerFirst(page1Resp.res.headers, 'etag');
      page1Etag = rotated && VALID_ETAG_RE.test(rotated) ? rotated : sendPage1Etag;

      // Fast path: single-page repository returned 304 -> zero extra requests!
      if (!knownMultiPage) {
        if (cachedPage1 && page1Etag) {
          cachedPage1.etag = page1Etag;
          cachedPage1.usedAt = this.now();
        }
        return {
          notModified: true,
          pulls: [],
          etag: page1Etag,
          etagKey,
          truncated: false,
          pageCount: 1,
        };
      }

      // Multi-page repo: reconstruct page 1 from in-memory cache and validate page 2+
      page1RawText = cachedPage1!.body;
      page1Link = headerFirst(page1Resp.res.headers, 'link') || cachedPage1!.link || '';
    } else {
      const respEtag = headerFirst(page1Resp.res.headers, 'etag');
      page1Etag = respEtag && VALID_ETAG_RE.test(respEtag) ? respEtag : undefined;
      page1RawText = page1Resp.res.body.toString('utf8');
      page1Link = headerFirst(page1Resp.res.headers, 'link');
    }

    const page1Items = JSON.parse(page1RawText) as RawGitHubPr[];
    if (!Array.isArray(page1Items)) {
      throw new Error(`Unexpected non-array response listing PRs for ${repoSlug}`);
    }

    const allPulls: PullRequestInfo[] = [];
    const seenNumbers = new Set<number>();
    const appendItems = (items: RawGitHubPr[]) => {
      for (const item of items) {
        const pr = parsePrObject(repoSlug, item);
        if (pr && !seenNumbers.has(pr.number)) {
          seenNumbers.add(pr.number);
          allPulls.push(pr);
        }
      }
    };
    appendItems(page1Items);

    const pendingCacheWrites: Array<{ key: string; entry: ETagEntry | null }> = [
      {
        key: etagKey,
        entry: page1Etag
          ? { etag: page1Etag, body: page1RawText, link: page1Link, usedAt: this.now() }
          : null,
      },
    ];

    let truncated = false;
    let pageCount = 1;
    let hasMore =
      (page1Items.length === 100 && (page1Link === '' || hasNextPageLink(page1Link))) ||
      (knownMultiPage && page1Items.length === 100);

    for (let page = 2; hasMore && page <= maxPages; page++) {
      const pagePath = makePagePath(page);
      const pageCacheKey = this.makeEtagKey(tokenInfo.principalFingerprint, pagePath);
      const cachedPage = this.etagCache.get(pageCacheKey);
      const sendPageEtag = !effectiveBypassEtag && cachedPage ? cachedPage.etag : undefined;

      const nextResp = await this.request({
        method: 'GET',
        path: pagePath,
        etag: sendPageEtag,
        resource: 'core',
        priority: opts?.priority ?? 'core',
        signal: opts?.signal,
      });

      let pageRawText: string;
      let pageLink: string;
      let freshLink = '';
      let pageEtag: string | undefined;

      if (nextResp.res.status === 304 && cachedPage) {
        const rotated = headerFirst(nextResp.res.headers, 'etag');
        pageEtag = rotated && VALID_ETAG_RE.test(rotated) ? rotated : cachedPage.etag;
        pageRawText = cachedPage.body;
        freshLink = headerFirst(nextResp.res.headers, 'link');
        if (cachedPage.link && hasNextPageLink(cachedPage.link) && freshLink && !hasNextPageLink(freshLink)) {
          anyPageModified = true;
        }
        pageLink = freshLink || cachedPage.link || '';
      } else {
        anyPageModified = true;
        const respEtag = headerFirst(nextResp.res.headers, 'etag');
        pageEtag = respEtag && VALID_ETAG_RE.test(respEtag) ? respEtag : undefined;
        pageRawText = nextResp.res.body.toString('utf8');
        pageLink = headerFirst(nextResp.res.headers, 'link');
        freshLink = pageLink;
      }

      const items = JSON.parse(pageRawText) as RawGitHubPr[];
      if (!Array.isArray(items)) {
        throw new Error(`Unexpected non-array response listing PRs page ${page} for ${repoSlug}`);
      }
      if (items.length === 0) {
        // Evict stale trailing page from etagCache and clear stale rel="next" on the terminal non-empty page!
        pendingCacheWrites.push({ key: pageCacheKey, entry: null });
        const prevWrite = pendingCacheWrites[pendingCacheWrites.length - 2];
        if (prevWrite?.entry) {
          prevWrite.entry.link = '';
          prevWrite.entry.hasNonEmptyNextPage = false;
        }
        break;
      }
      pageCount = page;
      pendingCacheWrites.push({
        key: pageCacheKey,
        entry: pageEtag
          ? { etag: pageEtag, body: pageRawText, link: pageLink, usedAt: this.now() }
          : null,
      });
      appendItems(items);
      const cachedTerminalPage =
        nextResp.res.status === 304 &&
        cachedPage?.hasNonEmptyNextPage === false &&
        !hasNextPageLink(freshLink);
      hasMore = cachedTerminalPage
        ? opts?.previousPageCount !== undefined && page < opts.previousPageCount
        : (items.length === 100 && (pageLink === '' || hasNextPageLink(pageLink))) ||
          (opts?.previousPageCount !== undefined && page < opts.previousPageCount);
      if (page === maxPages && hasMore) {
        truncated = true;
      }
    }

    // Only commit per-page ETags AFTER all pages succeed (prevents poisoning on page 2+ errors).
    // Mark `hasNonEmptyNextPage` accurately on EVERY non-null page entry so exact 100/200-PR repos
    // never hammer empty trailing pages on subsequent 304 polls!
    let nonEmptyIdx = 0;
    for (const write of pendingCacheWrites) {
      if (write.entry) {
        nonEmptyIdx++;
        write.entry.hasNonEmptyNextPage = nonEmptyIdx < pageCount;
      }
    }
    if (!opts?.bypassEtag) {
      for (const write of pendingCacheWrites) {
        if (write.entry) {
          this.putEtagEntry(write.key, write.entry);
        } else {
          this.etagCache.delete(write.key);
        }
      }
    }

    if (!anyPageModified) {
      return {
        notModified: true,
        pulls: [],
        etag: page1Etag,
        etagKey,
        truncated: false,
        pageCount,
      };
    }

    return {
      notModified: false,
      pulls: allPulls,
      etag: page1Etag,
      etagKey,
      truncated,
      pageCount,
    };
  }

  async getPullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    opts?: { priority?: 'core' | 'non_core'; bypassPauseCheck?: boolean; signal?: AbortSignal },
  ): Promise<PullRequestInfo> {
    const repoSlug = `${owner}/${repo}`;
    const { res } = await this.request({
      method: 'GET',
      path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}`,
      resource: 'core',
      priority: opts?.priority ?? 'core',
      bypassPauseCheck: opts?.bypassPauseCheck,
      signal: opts?.signal,
    });
    const raw = JSON.parse(res.body.toString('utf8')) as RawGitHubPr;
    const pr = parsePrObject(repoSlug, raw);
    if (!pr) {
      throw new Error(`Invalid pull request payload for ${repoSlug}#${prNumber}`);
    }
    return pr;
  }

  async listIssueComments(
    owner: string,
    repo: string,
    issueNumber: number,
    opts?: { maxPages?: number; stopWhen?: (comment: IssueComment) => boolean },
  ): Promise<{ comments: IssueComment[]; truncated: boolean }> {
    const maxPages = Math.max(1, Math.min(opts?.maxPages ?? 50, 100));
    const all: IssueComment[] = [];
    let truncated = false;

    for (let page = 1; page <= maxPages; page++) {
      const { res } = await this.request({
        method: 'GET',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments?per_page=100&page=${page}`,
        resource: 'core',
        priority: 'non_core',
      });
      const raw = JSON.parse(res.body.toString('utf8')) as Array<{
        id?: unknown;
        body?: unknown;
        html_url?: unknown;
        user?: { login?: unknown } | null;
      }>;
      if (!Array.isArray(raw) || raw.length === 0) break;

      for (const c of raw) {
        if (typeof c.id !== 'number') continue;
        const item: IssueComment = {
          id: c.id,
          body: typeof c.body === 'string' ? c.body : '',
          htmlUrl: typeof c.html_url === 'string' ? c.html_url : '',
          userLogin: typeof c.user?.login === 'string' ? c.user.login : 'unknown',
        };
        all.push(item);
        if (opts?.stopWhen?.(item)) {
          return { comments: all, truncated: false };
        }
      }

      const link = headerFirst(res.headers, 'link');
      const hasMore = raw.length === 100 && (link === '' || hasNextPageLink(link));
      if (!hasMore) break;
      if (page === maxPages) {
        truncated = true;
      }
    }

    return { comments: all, truncated };
  }

  async getIssueComment(
    owner: string,
    repo: string,
    commentId: number,
  ): Promise<IssueComment | null> {
    try {
      const { res } = await this.request({
        method: 'GET',
        path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${commentId}`,
        resource: 'core',
        priority: 'non_core',
      });
      const c = JSON.parse(res.body.toString('utf8')) as {
        id?: unknown;
        body?: unknown;
        html_url?: unknown;
        user?: { login?: unknown } | null;
      };
      if (typeof c.id !== 'number') return null;
      return {
        id: c.id,
        body: typeof c.body === 'string' ? c.body : '',
        htmlUrl: typeof c.html_url === 'string' ? c.html_url : '',
        userLogin: typeof c.user?.login === 'string' ? c.user.login : 'unknown',
      };
    } catch (err) {
      if (err instanceof GitHubApiError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async createIssueComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string,
  ): Promise<IssueComment> {
    const { res } = await this.request({
      method: 'POST',
      path: `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments`,
      body: { body },
      resource: 'core',
      priority: 'core',
    });
    const parsed = JSON.parse(res.body.toString('utf8')) as {
      id?: unknown;
      body?: unknown;
      html_url?: unknown;
      user?: { login?: unknown } | null;
    };
    return {
      id: typeof parsed.id === 'number' ? parsed.id : 0,
      body: typeof parsed.body === 'string' ? parsed.body : body,
      htmlUrl: typeof parsed.html_url === 'string' ? parsed.html_url : '',
      userLogin: typeof parsed.user?.login === 'string' ? parsed.user.login : 'unknown',
    };
  }

  /**
   * Search endpoint helper explicitly routed through the `search` rate-limit bucket
   * so search quota exhaustion never pollutes core quota.
   */
  async searchIssues(query: string): Promise<unknown> {
    const { res } = await this.request({
      method: 'GET',
      path: `/search/issues?q=${encodeURIComponent(query)}&per_page=30`,
      resource: 'search',
      priority: 'non_core',
    });
    return JSON.parse(res.body.toString('utf8'));
  }

  async testAuth(opts?: { repo?: string; timeoutMs?: number }): Promise<AuthTestResult> {
    const timeoutMs = opts?.timeoutMs ?? 8_000;
    try {
      const resolved = await this.authManager.getToken();
      let identity = '';
      let scopes: string[] | undefined;

      if (resolved.method === 'github_app') {
        // GitHub App installation tokens cannot call GET /user (returns 403).
        const { res } = await this.request({
          method: 'GET',
          path: '/installation/repositories?per_page=1',
          bypassPauseCheck: true,
          timeoutMs,
        });
        const data = JSON.parse(res.body.toString('utf8')) as { total_count?: number };
        identity = `app:${this.authConfig.app.appId}/installation:${this.authConfig.app.installationId} (${data.total_count ?? 0} repos)`;
      } else {
        const { res } = await this.request({
          method: 'GET',
          path: '/user',
          bypassPauseCheck: true,
          timeoutMs,
        });
        const data = JSON.parse(res.body.toString('utf8')) as { login?: string };
        identity = data.login ? `@${data.login}` : 'authenticated';
        const rawScopes = headerFirst(res.headers, 'x-oauth-scopes');
        if (rawScopes) {
          scopes = rawScopes
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
        }
      }

      let repoAccess: AuthTestResult['repoAccess'];
      if (opts?.repo !== undefined && opts.repo.trim() !== '') {
        try {
          const validSlug = validateRepoSlug(opts.repo);
          const [owner, repo] = validSlug.split('/');
          await this.request({
            method: 'GET',
            path: `/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(repo!)}`,
            bypassPauseCheck: true,
            timeoutMs,
          });
          repoAccess = { repo: validSlug, ok: true };
        } catch (err) {
          repoAccess = {
            repo: opts.repo.trim(),
            ok: false,
            error: formatSafeError(err, this.registry),
          };
        }
      }

      const snap = this.rateLimits.snapshot();
      const topOk = repoAccess ? repoAccess.ok : true;
      return {
        ok: topOk,
        authMode: this.authConfig.mode,
        resolvedMethod: resolved.method,
        apiBaseUrl: this.authConfig.apiBaseUrl.toString(),
        identity,
        ...(scopes ? { scopes } : {}),
        ...(snap.core ? { rateLimit: snap.core } : {}),
        ...(repoAccess ? { repoAccess } : {}),
        ...(!topOk
          ? {
              error: `Repository access check failed for ${repoAccess!.repo}: ${repoAccess!.error ?? 'forbidden'}`,
            }
          : {}),
      };
    } catch (err) {
      return {
        ok: false,
        authMode: this.authConfig.mode,
        apiBaseUrl: this.authConfig.apiBaseUrl.toString(),
        error: formatSafeError(err, this.registry),
      };
    }
  }
}
