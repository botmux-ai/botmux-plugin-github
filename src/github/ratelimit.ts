import type { RateLimitState, ResourceRateLimit } from '../types.ts';

const PAUSE_FIRST_MS = 60_000; // 1 minute
const PAUSE_LONGEST_MS = 3_600_000; // 1 hour

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string {
  const lower = name.toLowerCase();
  const val = headers[lower] ?? headers[name];
  if (Array.isArray(val)) return val[0] ?? '';
  return typeof val === 'string' ? val.trim() : '';
}

export function isRateLimitedResponse(
  status: number,
  headers: Record<string, string | string[] | undefined>,
  errorMessage: string,
): boolean {
  if (status === 429) return true;
  if (status !== 403) return false;
  const lower = errorMessage.toLowerCase();
  if (lower.includes('rate limit') || lower.includes('abuse detection')) {
    return true;
  }
  if (headerValue(headers, 'retry-after') !== '') {
    return true;
  }
  if (headerValue(headers, 'x-ratelimit-remaining') === '0') {
    return true;
  }
  return false;
}

function parseRetryAfter(raw: string, nowMs: number): number | null {
  if (!raw) return null;
  if (/^\d+$/.test(raw)) {
    const secs = Number(raw);
    if (secs > 0) return nowMs + secs * 1000;
    return null;
  }
  const parsedDate = Date.parse(raw);
  if (!Number.isNaN(parsedDate) && parsedDate > nowMs) {
    return parsedDate;
  }
  return null;
}

/**
 * GitHub per-resource rate limit & secondary backoff tracker:
 * - Tracks `core` (including empty X-RateLimit-Resource) and `search` independently;
 *   untracked resources (graphql, code_search, integration_manifest) never pollute core.
 * - Strict integer `< 10%` threshold (`remaining * 10 < limit`) marks resource low
 *   so non-core background requests pause while core critical operations proceed.
 * - Secondary 429/403 pause precedence:
 *   1. Retry-After (integer seconds or HTTP date)
 *   2. X-RateLimit-Reset ONLY when X-RateLimit-Remaining == "0" and resource is core/empty
 *   3. Monotonic exponential backoff 1m -> 2m -> 4m -> 8m -> 16m -> 32m -> 1h
 * - Coalesces concurrent hits during an active pause, never shortens pausedUntil,
 *   explicit Retry-After/Reset pauses never modify pauseStep/backoffUntil, and
 *   pauseStep only resets after a quiet window of 1*pauseStep past backoffUntil
 *   (NOT on a single 200 OK!).
 */
export class RateLimitTracker {
  private core?: ResourceRateLimit;
  private search?: ResourceRateLimit;
  private pausedUntilMs = 0;
  private pauseStepMs = 0;
  private backoffUntilMs = 0;
  private readonly now: () => number;

  constructor(opts?: { initial?: RateLimitState; now?: () => number }) {
    this.now = opts?.now ?? (() => Date.now());
    if (opts?.initial) {
      this.restore(opts.initial);
    }
  }

  restore(state: RateLimitState): void {
    if (state.core) this.core = { ...state.core };
    if (state.search) this.search = { ...state.search };
    if (state.pausedUntil) {
      const ts = Date.parse(state.pausedUntil);
      if (!Number.isNaN(ts)) this.pausedUntilMs = ts;
    }
    if (typeof state.pauseStepMs === 'number' && state.pauseStepMs >= 0) {
      this.pauseStepMs = state.pauseStepMs;
    }
    if (state.backoffUntil) {
      const ts = Date.parse(state.backoffUntil);
      if (!Number.isNaN(ts)) this.backoffUntilMs = ts;
    }
  }

  snapshot(): RateLimitState {
    const nowMs = this.now();
    const out: RateLimitState = {
      lastUpdatedAt: new Date(nowMs).toISOString(),
    };
    if (this.core) {
      const resetMs = Date.parse(this.core.resetAt);
      out.core = {
        ...this.core,
        low: this.core.low && !Number.isNaN(resetMs) && nowMs < resetMs,
      };
    }
    if (this.search) {
      const resetMs = Date.parse(this.search.resetAt);
      out.search = {
        ...this.search,
        low: this.search.low && !Number.isNaN(resetMs) && nowMs < resetMs,
      };
    }
    if (this.pausedUntilMs > nowMs) {
      out.pausedUntil = new Date(this.pausedUntilMs).toISOString();
    }
    if (this.pauseStepMs > 0) {
      out.pauseStepMs = this.pauseStepMs;
    }
    if (this.backoffUntilMs > 0) {
      out.backoffUntil = new Date(this.backoffUntilMs).toISOString();
    }
    return out;
  }

  noteHeaders(headers: Record<string, string | string[] | undefined>): void {
    const limitRaw = headerValue(headers, 'x-ratelimit-limit');
    const remRaw = headerValue(headers, 'x-ratelimit-remaining');
    const resetRaw = headerValue(headers, 'x-ratelimit-reset');
    if (!limitRaw || !remRaw || !resetRaw) return;

    const limit = Number.parseInt(limitRaw, 10);
    const remaining = Number.parseInt(remRaw, 10);
    const resetSec = Number.parseInt(resetRaw, 10);
    if (!Number.isFinite(limit) || limit <= 0 || !Number.isFinite(remaining) || !Number.isFinite(resetSec)) {
      return;
    }

    const resource = headerValue(headers, 'x-ratelimit-resource').toLowerCase();
    // Exact integer threshold strictly < 10%
    const low = remaining * 10 < limit;
    const entry: ResourceRateLimit = {
      limit,
      remaining: Math.max(0, remaining),
      resetAt: new Date(resetSec * 1000).toISOString(),
      low,
    };

    if (resource === '' || resource === 'core') {
      this.core = entry;
    } else if (resource === 'search') {
      this.search = entry;
    }
    // Untracked resources (graphql, code_search, integration_manifest, etc.) are intentionally ignored.
  }

  notePause(
    status: number,
    headers: Record<string, string | string[] | undefined>,
    errorMessage: string,
  ): boolean {
    if (!isRateLimitedResponse(status, headers, errorMessage)) {
      return false;
    }

    const nowMs = this.now();
    const resource = headerValue(headers, 'x-ratelimit-resource').toLowerCase();
    const retryAfterRaw = headerValue(headers, 'retry-after');
    const usedUp = headerValue(headers, 'x-ratelimit-remaining') === '0';

    // Non-core quota exhaustion without Retry-After must NOT trigger a global pause.
    if (usedUp && resource !== '' && resource !== 'core' && retryAfterRaw === '') {
      return true;
    }

    let untilMs = 0;

    // 1. Retry-After (int seconds or HTTP date) — never alters pauseStep / backoffUntil
    const retryUntil = parseRetryAfter(retryAfterRaw, nowMs);
    if (retryUntil !== null) {
      untilMs = retryUntil;
    }

    // 2. X-RateLimit-Reset ONLY when remaining == 0 (core) and in future — never alters pauseStep
    if (untilMs === 0 && usedUp) {
      const resetRaw = headerValue(headers, 'x-ratelimit-reset');
      const resetSec = Number.parseInt(resetRaw, 10);
      if (Number.isFinite(resetSec) && resetSec * 1000 > nowMs) {
        untilMs = resetSec * 1000;
      }
    }

    // 3. Monotonic exponential backoff 1m -> 2m -> ... -> 1h
    if (untilMs === 0) {
      if (nowMs < this.pausedUntilMs) {
        // Coalesce concurrent secondary rate-limit hits during an active pause
        return true;
      }
      let step = PAUSE_FIRST_MS;
      if (this.pauseStepMs > 0 && nowMs < this.backoffUntilMs + this.pauseStepMs) {
        step = Math.min(this.pauseStepMs * 2, PAUSE_LONGEST_MS);
      }
      this.pauseStepMs = step;
      this.backoffUntilMs = nowMs + step;
      untilMs = this.backoffUntilMs;
    }

    if (untilMs > this.pausedUntilMs) {
      this.pausedUntilMs = untilMs;
    }
    return true;
  }

  pauseRemainingMs(): number {
    return Math.max(0, this.pausedUntilMs - this.now());
  }

  isGloballyPaused(): boolean {
    return this.pauseRemainingMs() > 0;
  }

  isCoreLow(): boolean {
    if (!this.core || !this.core.low) return false;
    const resetMs = Date.parse(this.core.resetAt);
    return !Number.isNaN(resetMs) && this.now() < resetMs;
  }

  isSearchLow(): boolean {
    if (!this.search || !this.search.low) return false;
    const resetMs = Date.parse(this.search.resetAt);
    return !Number.isNaN(resetMs) && this.now() < resetMs;
  }

  /**
   * Determines whether a request of the given priority/resource should be
   * paused before sending:
   * - Global pause (429 / secondary 403 / core exhausted) blocks all background requests.
   * - Core < 10% blocks non-core background requests (`priority === 'non_core'`).
   * - Search < 10% blocks search requests (`resource === 'search'`).
   */
  shouldPause(opts: { resource?: 'core' | 'search'; priority?: 'core' | 'non_core' } = {}): {
    paused: boolean;
    reason?: string;
    until?: string;
  } {
    const nowMs = this.now();
    if (nowMs < this.pausedUntilMs) {
      return {
        paused: true,
        reason: 'secondary_or_exhausted_rate_limit',
        until: new Date(this.pausedUntilMs).toISOString(),
      };
    }
    if (opts.resource === 'search' && this.isSearchLow()) {
      return {
        paused: true,
        reason: 'search_quota_below_10_percent',
        until: this.search?.resetAt,
      };
    }
    if (opts.priority === 'non_core' && this.isCoreLow()) {
      return {
        paused: true,
        reason: 'core_quota_below_10_percent',
        until: this.core?.resetAt,
      };
    }
    return { paused: false };
  }
}
