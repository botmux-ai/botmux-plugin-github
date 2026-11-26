import type {
  AuthTestResult,
  EventKind,
  OpenPrResult,
  PluginConfig,
  PullRequestInfo,
  RateLimitState,
  RepoRule,
  ServiceMode,
  SyncActionPreview,
  SyncResult,
} from '../types.ts';
import {
  computeRuleFilterHash,
  normalizeRepoKey,
  registerConfigSecrets,
  validateRepoSlug,
} from '../config/schema.ts';
import { StateStore, makeEventDedupKey, makePrKey } from '../state/store.ts';
import {
  GitHubClient,
  GitHubRateLimitPausedError,
} from '../github/client.ts';
import type { GhCliRunner } from '../github/auth.ts';
import { HostBridge, isPrGroupComplete } from '../host/bridge.ts';
import type { DiscoveryOptions } from '../host/discovery.ts';
import type { LarkOpenApiClient } from '../host/lark.ts';
import type { CliExecFn } from '../host/bridge.ts';
import { SecretRegistry, defaultSecretRegistry, formatSafeError } from '../security/redact.ts';
import { buildKickoffPrompt, renderSafeGroupName } from '../security/sanitize.ts';
import { buildNewCommitMessage, buildPrClosedMessage, evaluateRepoRule } from './rules.ts';
import { PerPrSerialQueue } from './queue.ts';
import { DeliveryDedupCache } from './webhook.ts';

export interface GitHubWatcherOptions {
  config: PluginConfig;
  stateStore: StateStore;
  discovery?: DiscoveryOptions;
  registry?: SecretRegistry;
  ghRunner?: GhCliRunner;
  larkClient?: LarkOpenApiClient;
  cliExec?: CliExecFn;
  allowInsecureLocalApiForTests?: boolean;
  maxPendingPerKey?: number;
  maxGlobalPending?: number;
  maxInFlightDeliveries?: number;
  inFlightDeliveryTimeoutMs?: number;
  taskTimeoutMs?: number;
  now?: () => number;
}

export type WebhookEnqueueVerdict =
  | { accepted: true }
  | { accepted: false; status: 429 | 503; reason: string };

interface GenerationGuard {
  gen?: number;
  repoKey?: string;
  signal?: AbortSignal;
}

class GenerationAbortedError extends Error {
  readonly code = 'GENERATION_ABORTED';
  constructor() {
    super('Watcher generation aborted');
    this.name = 'AbortError';
  }
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === 'AbortError' || (err as { code?: string }).code === 'GENERATION_ABORTED');
}

export class GitHubWatcher {
  private config: PluginConfig;
  private readonly stateStore: StateStore;
  private readonly discovery?: DiscoveryOptions;
  private readonly registry: SecretRegistry;
  private readonly ghRunner?: GhCliRunner;
  private readonly larkClient?: LarkOpenApiClient;
  private readonly cliExec?: CliExecFn;
  private readonly allowInsecureLocalApiForTests: boolean;
  private readonly now: () => number;

  private githubClient: GitHubClient | null = null;
  private hostBridge: HostBridge | null = null;
  private readonly queue: PerPrSerialQueue;
  readonly deliveryDedup: DeliveryDedupCache;

  private pollTimers = new Map<string, ReturnType<typeof setInterval>>();
  private pollInFlight = new Map<string, Promise<SyncActionPreview[]>>();
  private generation = 0;
  private generationAbort = new AbortController();
  private started = false;
  private startedAtIso: string;

  constructor(opts: GitHubWatcherOptions) {
    this.config = opts.config;
    this.stateStore = opts.stateStore;
    this.discovery = opts.discovery;
    this.registry = opts.registry ?? defaultSecretRegistry;
    this.ghRunner = opts.ghRunner;
    this.larkClient = opts.larkClient;
    this.cliExec = opts.cliExec;
    this.allowInsecureLocalApiForTests = opts.allowInsecureLocalApiForTests === true;
    this.now = opts.now ?? (() => Date.now());
    this.startedAtIso = new Date(this.now()).toISOString();

    this.deliveryDedup = new DeliveryDedupCache({
      maxInFlight: opts.maxInFlightDeliveries,
      inFlightTimeoutMs: opts.inFlightDeliveryTimeoutMs,
      now: this.now,
    });
    this.queue = new PerPrSerialQueue({
      maxConcurrency: 4,
      maxPendingPerKey: opts.maxPendingPerKey ?? 32,
      maxGlobalPending: opts.maxGlobalPending ?? 256,
      taskTimeoutMs: opts.taskTimeoutMs ?? 120_000,
      onError: (key, err) => {
        if (isAbortError(err)) return;
        void this.stateStore
          .appendEvent({
            level: 'error',
            kind: 'pr_queue_error',
            message: `Error processing ${key}: ${formatSafeError(err, this.registry)}`,
          })
          .catch(() => {});
      },
    });
  }

  getConfig(): PluginConfig {
    return this.config;
  }

  getEnabledRules(): RepoRule[] {
    return this.config.repos.filter(r => r.enabled);
  }

  getAllowedRepoKeys(): Set<string> {
    return new Set(this.getEnabledRules().map(r => normalizeRepoKey(r.repo)));
  }

  getMode(): ServiceMode {
    if (this.getEnabledRules().length === 0) {
      return 'dormant';
    }
    if (this.githubClient?.rateLimits.isGloballyPaused()) {
      return 'paused';
    }
    return 'active';
  }

  getQueueStats(): { active: number; queued: number; pending: number } {
    return this.queue.stats();
  }

  private bumpGeneration(): void {
    this.generation++;
    const oldAbort = this.generationAbort;
    this.generationAbort = new AbortController();
    oldAbort.abort();
  }

  private isGuardActive(guard?: GenerationGuard): boolean {
    if (!guard) return true;
    if (guard.signal?.aborted) return false;
    if (guard.gen !== undefined) {
      if (guard.gen !== this.generation || this.generationAbort.signal.aborted) {
        return false;
      }
    }
    if (guard.repoKey !== undefined) {
      if (this.getEnabledRules().length === 0) return false;
      const liveRule = this.findRuleByRepo(guard.repoKey);
      if (!liveRule || !liveRule.enabled) return false;
    }
    return true;
  }

  private isGenerationCurrent(gen: number, signal?: AbortSignal): boolean {
    return this.isGuardActive({ gen, signal });
  }

  private assertGenerationCurrent(guard?: GenerationGuard): void {
    if (guard && !this.isGuardActive(guard)) {
      throw new GenerationAbortedError();
    }
  }

  private buildClientsForConfig(
    cfg: PluginConfig,
    initialRateLimits?: RateLimitState,
  ): { github: GitHubClient; bridge: HostBridge } {
    registerConfigSecrets(cfg, this.registry);
    const github = new GitHubClient({
      auth: cfg.github,
      proxy: cfg.proxy,
      initialRateLimits,
      registry: this.registry,
      ghRunner: this.ghRunner,
      allowInsecureLocalForTests: this.allowInsecureLocalApiForTests,
      now: this.now,
    });
    const bridge = new HostBridge({
      stateStore: this.stateStore,
      discovery: this.discovery,
      proxy: cfg.proxy,
      registry: this.registry,
      larkClient: this.larkClient,
      cliExec: this.cliExec,
      now: this.now,
    });
    return { github, bridge };
  }

  private ensureClients(initialRateLimits?: RateLimitState): {
    github: GitHubClient;
    bridge: HostBridge;
  } {
    registerConfigSecrets(this.config, this.registry);
    if (!this.githubClient || !this.hostBridge) {
      const built = this.buildClientsForConfig(this.config, initialRateLimits);
      if (!this.githubClient) this.githubClient = built.github;
      if (!this.hostBridge) this.hostBridge = built.bridge;
    }
    return { github: this.githubClient, bridge: this.hostBridge };
  }

  /**
   * Starts the watcher:
   * - If ZERO enabled repo rules exist, strictly stays in DORMANT mode:
   *   ZERO GitHub API requests, ZERO Feishu/daemon calls, ZERO poll timers!
   */
  async start(): Promise<void> {
    this.started = true;
    this.queue.resetForRestart();
    this.bumpGeneration();
    registerConfigSecrets(this.config, this.registry);

    const state = await this.stateStore.load();
    this.deliveryDedup.hydrate(state.processedDeliveries);

    const enabled = this.getEnabledRules();
    await this.stateStore.update(s => {
      s.service = {
        ...s.service,
        mode: enabled.length === 0 ? 'dormant' : 'active',
        startedAt: this.startedAtIso,
        lastHeartbeatAt: new Date(this.now()).toISOString(),
        activeRepoCount: enabled.length,
      };
    });

    if (enabled.length === 0) {
      this.clearTimers();
      return;
    }

    this.ensureClients(state.rateLimits);
    this.armPollTimers();
  }

  /**
   * Hot-reloads config transactionally:
   * - Pre-builds and validates candidate clients BEFORE touching state.json,
   *   active timers, or generation so invalid configs never corrupt running state.
   * - On commit, bumps generation & aborts old AbortController so in-flight polls
   *   or webhook handlers immediately halt when switching active -> dormant.
   */
  async reloadConfig(nextConfig: PluginConfig): Promise<ServiceMode> {
    const prevConfig = this.config;
    const prevGithub = this.githubClient;
    const prevBridge = this.hostBridge;

    const nextEnabled = nextConfig.repos.filter(r => r.enabled);
    const nextMode: ServiceMode = nextEnabled.length === 0 ? 'dormant' : 'active';

    const state = await this.stateStore.load();
    const prevServiceSnapshot = { ...state.service };

    // 1. Validate & build candidate clients BEFORE mutating state.json or timers
    let candidateGithub: GitHubClient | null = null;
    let candidateBridge: HostBridge | null = null;
    if (nextEnabled.length > 0) {
      const built = this.buildClientsForConfig(nextConfig, state.rateLimits);
      candidateGithub = built.github;
      candidateBridge = built.bridge;
    } else {
      registerConfigSecrets(nextConfig, this.registry);
    }

    // 2. Persist state.json service mode; rollback cleanly if commit/arming fails
    let stateUpdated = false;
    try {
      await this.stateStore.update(s => {
        s.service = {
          ...s.service,
          mode: nextMode,
          activeRepoCount: nextEnabled.length,
          lastReloadAt: new Date(this.now()).toISOString(),
          lastHeartbeatAt: new Date(this.now()).toISOString(),
        };
      });
      stateUpdated = true;

      this.clearTimers();
      this.bumpGeneration();
      this.config = nextConfig;
      this.githubClient = candidateGithub;
      this.hostBridge = candidateBridge;

      if (this.started && nextEnabled.length > 0) {
        this.armPollTimers();
      }
      return nextMode;
    } catch (err) {
      this.clearTimers();
      this.config = prevConfig;
      this.githubClient = prevGithub;
      this.hostBridge = prevBridge;
      if (stateUpdated) {
        await this.stateStore
          .update(s => {
            s.service = prevServiceSnapshot;
          })
          .catch(() => {});
      }
      if (this.started && prevConfig.repos.some(r => r.enabled)) {
        this.armPollTimers();
      }
      throw err;
    }
  }

  async stop(drainTimeoutMs = 7_000): Promise<void> {
    this.started = false;
    this.clearTimers();
    this.bumpGeneration();
    await this.queue.drain(drainTimeoutMs);
    if (this.githubClient) {
      await this.persistRateLimits();
    }
  }

  private clearTimers(): void {
    for (const timer of this.pollTimers.values()) {
      clearInterval(timer);
    }
    this.pollTimers.clear();
  }

  private armPollTimers(): void {
    this.clearTimers();
    for (const rule of this.getEnabledRules()) {
      const repoKey = normalizeRepoKey(rule.repo);
      const intervalMs =
        Math.max(15, rule.pollIntervalSec ?? this.config.service.pollIntervalSec) * 1000;

      void this.pollRepo(rule, { dryRun: false, waitForInFlight: false }).catch(err => {
        if (isAbortError(err)) return;
        void this.stateStore
          .appendEvent({
            level: 'error',
            kind: 'poll_error',
            repo: rule.repo,
            message: `Initial poll failed: ${formatSafeError(err, this.registry)}`,
          })
          .catch(() => {});
      });

      const timer = setInterval(() => {
        void this.pollRepo(rule, { dryRun: false, waitForInFlight: false }).catch(err => {
          if (isAbortError(err)) return;
          void this.stateStore
            .appendEvent({
              level: 'error',
              kind: 'poll_error',
              repo: rule.repo,
              message: `Scheduled poll failed: ${formatSafeError(err, this.registry)}`,
            })
            .catch(() => {});
        });
      }, intervalMs);
      timer.unref?.();
      this.pollTimers.set(repoKey, timer);
    }
  }

  private async persistRateLimits(expectedGen?: number): Promise<void> {
    if (!this.githubClient) return;
    if (expectedGen !== undefined && !this.isGenerationCurrent(expectedGen)) return;
    const snap = this.githubClient.rateLimits.snapshot();
    await this.stateStore.update(s => {
      if (expectedGen !== undefined && !this.isGenerationCurrent(expectedGen)) return;
      s.rateLimits = snap;
      // Compute live mode INSIDE the lock so an old active poll can never overwrite dormant state!
      s.service.mode = this.getMode();
      s.service.lastHeartbeatAt = new Date(this.now()).toISOString();
    });
  }

  private findRuleByRepo(repo: string): RepoRule | undefined {
    const target = normalizeRepoKey(repo);
    return this.config.repos.find(r => normalizeRepoKey(r.repo) === target);
  }

  private async invalidateRepoEtag(repoKey: string): Promise<void> {
    this.githubClient?.clearEtagCache();
    await this.stateStore
      .update(s => {
        const r = s.repos[repoKey];
        if (r) {
          delete r.etag;
          delete r.etagKey;
        }
      })
      .catch(() => {});
  }

  /**
   * Synchronously admits or rejects a verified GitHub pull_request webhook event.
   * When the per-PR or global queue is full or draining, aborts deliveryDedup and
   * returns `{ accepted: false, status: 429 | 503 }` synchronously so HTTP never
   * sends a fake 202 Accepted!
   */
  enqueueWebhookPrEvent(opts: {
    deliveryId: string;
    action: string;
    pr: PullRequestInfo;
  }): WebhookEnqueueVerdict {
    const rule = this.findRuleByRepo(opts.pr.repo);
    if (!rule || !rule.enabled || this.queue.isStopping()) {
      this.deliveryDedup.abort(opts.deliveryId);
      return {
        accepted: false,
        status: 503,
        reason: 'service_stopping_or_rule_disabled',
      };
    }

    const repoKey = normalizeRepoKey(rule.repo);
    const prKey = makePrKey(rule.repo, opts.pr.number);
    // Do NOT tie already-202-accepted webhooks to pollGeneration so active->active reloads
    // (e.g. changing pollIntervalSec) never silently drop queued webhooks!
    // Instead, guard by live repo enabled status so active->dormant or disabling the repo still aborts cleanly.
    const enq = this.queue.tryEnqueue(prKey, async taskSignal => {
      const guard: GenerationGuard = { repoKey, signal: taskSignal };
      this.assertGenerationCurrent(guard);
      const liveRule = this.findRuleByRepo(repoKey);
      if (!liveRule || !liveRule.enabled) {
        throw new GenerationAbortedError();
      }
      await this.processWebhookPrEvent(liveRule, opts.action, opts.pr, guard);
      this.assertGenerationCurrent(guard);
      this.deliveryDedup.commit(opts.deliveryId);
      await this.stateStore.recordDelivery(opts.deliveryId);
    });

    if (!enq.accepted) {
      this.deliveryDedup.abort(opts.deliveryId);
      if (enq.reason === 'draining') {
        return { accepted: false, status: 503, reason: 'service_draining' };
      }
      return {
        accepted: false,
        status: 429,
        reason: enq.reason === 'global_full' ? 'global_queue_full' : 'pr_queue_full',
      };
    }

    enq.promise.catch(err => {
      this.deliveryDedup.abort(opts.deliveryId);
      // Do NOT mutate state.json or emit spurious errors if aborted or if repo/watcher went dormant!
      if (isAbortError(err) || !this.isGuardActive({ repoKey })) {
        return;
      }
      void this.invalidateRepoEtag(repoKey);
      void this.stateStore
        .appendEvent({
          level: 'error',
          kind: 'webhook_process_error',
          repo: rule.repo,
          prNumber: opts.pr.number,
          message: `Failed processing webhook ${opts.action}: ${formatSafeError(err, this.registry)}`,
        })
        .catch(() => {});
    });

    return { accepted: true };
  }

  /**
   * Processes a webhook PR event WITHOUT committing `knownPrs` prematurely and
   * re-verifying generation/AbortSignal after every async step:
   * - Never commits `knownPrs` before group creation / action succeeds.
   * - On `synchronize`, refuses to commit `knownPrs` (and clears repo ETag) whenever
   *   a pending lifecycle transition could be masked (unknown PR, draft->ready,
   *   closed->open, or non-active group).
   * - Invalidates repo ETag on group create/reactivate so a subsequent close returning
   *   open PRs to the previous list can never be masked by a 304 Not Modified!
   */
  private async processWebhookPrEvent(
    rule: RepoRule,
    action: string,
    pr: PullRequestInfo,
    guard: GenerationGuard,
  ): Promise<void> {
    this.assertGenerationCurrent(guard);

    const repoKey = normalizeRepoKey(rule.repo);
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    this.assertGenerationCurrent(guard);

    const repoState = state.repos[repoKey];
    const prevCursor = repoState?.knownPrs[String(pr.number)];
    const existingGroup = state.prGroups[prKey];

    const commitKnownCursor = async (stateVal: 'open' | 'closed' = pr.state) => {
      this.assertGenerationCurrent(guard);
      await this.stateStore.update(s => {
        if (!this.isGuardActive(guard)) return;
        const r = s.repos[repoKey] ?? { knownPrs: {} };
        r.knownPrs[String(pr.number)] = {
          headSha: pr.headSha,
          draft: pr.draft,
          state: stateVal,
          updatedAt: pr.updatedAt || new Date(this.now()).toISOString(),
        };
        s.repos[repoKey] = r;
      });
    };

    if (action === 'reopened') {
      const res = await this.handlePrReopened(rule, pr, false, guard);
      this.assertGenerationCurrent(guard);
      await this.invalidateRepoEtag(repoKey);
      // Do NOT commit knownPrs as open if deferred by hourly creation cap so next poll retries!
      if (res.action === 'skip_rate_limited') {
        return;
      }
      await commitKnownCursor('open');
      return;
    }

    if (action === 'opened' || action === 'ready_for_review') {
      const triggerKind = action === 'ready_for_review' ? 'ready_for_review' : 'opened';
      const match = evaluateRepoRule(rule, pr, triggerKind);
      if (match.matched) {
        const res = await this.handleGroupTrigger(rule, pr, triggerKind, false, undefined, guard);
        this.assertGenerationCurrent(guard);
        await this.invalidateRepoEtag(repoKey);
        // Do NOT mark knownPrs if deferred by hourly rate cap so subsequent poll retries!
        if (res.action === 'skip_rate_limited') {
          return;
        }
      }
      await commitKnownCursor('open');
      return;
    }

    if (action === 'synchronize') {
      const masksDiscovery = !prevCursor && !existingGroup;
      const masksDraftToReady = Boolean(prevCursor?.draft && !pr.draft && !existingGroup);
      const masksReopen = Boolean(
        prevCursor?.state === 'closed' && (!existingGroup || existingGroup.status === 'closed'),
      );
      const masksIncompleteGroup = Boolean(existingGroup && existingGroup.status !== 'active');

      if (masksDiscovery || masksDraftToReady || masksReopen || masksIncompleteGroup) {
        await this.invalidateRepoEtag(repoKey);
        return;
      }

      if (rule.onNewCommit && existingGroup && existingGroup.status === 'active' && existingGroup.chatId) {
        await this.handleNewCommit(rule, pr, existingGroup.lastHeadSha, false, guard);
      }
      await commitKnownCursor('open');
      return;
    }

    if (action === 'closed') {
      if (existingGroup) {
        if (rule.onPrClosed && existingGroup.chatId) {
          await this.handlePrClosed(rule, pr, false, guard);
        } else if (existingGroup.status !== 'closed') {
          await this.markGroupClosedIdempotently(rule.repo, pr.number, pr.headSha, guard);
        }
      }
      await commitKnownCursor('closed');
    }
  }

  private async markGroupClosedIdempotently(
    repo: string,
    prNumber: number,
    headSha: string,
    guard?: GenerationGuard,
  ): Promise<void> {
    this.assertGenerationCurrent(guard);
    const prKey = makePrKey(repo, prNumber);
    await this.stateStore.update(s => {
      if (guard && !this.isGuardActive(guard)) return;
      const g = s.prGroups[prKey];
      if (g) {
        g.status = 'closed';
        g.lastHeadSha = headSha;
        g.updatedAt = new Date(this.now()).toISOString();
      }
    });
  }

  /**
   * Explicit reopen lifecycle handler (used by BOTH poller and webhook):
   * - If a group exists for this PR, increments `lifecycleGeneration` and either
   *   completes unfinished kickoff/top-notice steps via HostBridge or reactivates directly.
   * - If no group exists yet, evaluates `opened` rule and creates a group with the new generation.
   */
  private async handlePrReopened(
    rule: RepoRule,
    pr: PullRequestInfo,
    dryRun: boolean,
    guard?: GenerationGuard,
  ): Promise<SyncActionPreview> {
    this.assertGenerationCurrent(guard);
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    this.assertGenerationCurrent(guard);
    const existingGroup = state.prGroups[prKey];

    if (existingGroup && existingGroup.chatId) {
      if (dryRun) {
        return {
          repo: rule.repo,
          prNumber: pr.number,
          action: 'resume_group',
          reason: 'reopened_reactivate',
          chatId: existingGroup.chatId,
        };
      }

      const nextGen = (existingGroup.lifecycleGeneration ?? 1) + 1;
      const needsCompletion = !isPrGroupComplete(
        { ...existingGroup, status: 'active' },
        rule,
      );

      if (needsCompletion) {
        // Bump generation and set status='creating' BEFORE delegating to bridge even if
        // existingGroup.status had not transitioned to 'closed' yet (e.g. onPrClosed was false).
        await this.stateStore.update(s => {
          if (guard && !this.isGuardActive(guard)) return;
          const g = s.prGroups[prKey];
          if (g) {
            g.lifecycleGeneration = nextGen;
            g.status = 'creating';
            g.lastHeadSha = pr.headSha;
            g.updatedAt = new Date(this.now()).toISOString();
          }
        });
        this.assertGenerationCurrent(guard);
        const { github, bridge } = this.ensureClients(state.rateLimits);
        const res = await bridge.ensurePrReviewGroup({ rule, pr, githubClient: github });
        return {
          repo: rule.repo,
          prNumber: pr.number,
          action: 'resume_group',
          reason: 'reopened_resumed_incomplete',
          chatId: res.record.chatId,
          groupName: res.record.groupName,
        };
      }

      await this.stateStore.update(s => {
        if (guard && !this.isGuardActive(guard)) return;
        const g = s.prGroups[prKey];
        if (g) {
          g.status = 'active';
          g.lifecycleGeneration = nextGen;
          g.lastHeadSha = pr.headSha;
          g.updatedAt = new Date(this.now()).toISOString();
        }
      });
      await this.stateStore.appendEvent({
        level: 'info',
        kind: 'pr_reopened_reactivated',
        repo: rule.repo,
        prNumber: pr.number,
        chatId: existingGroup.chatId,
        message: `Reactivated group ${existingGroup.chatId} on PR reopen (generation=${nextGen})`,
      });
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'resume_group',
        reason: 'reopened_reactivated',
        chatId: existingGroup.chatId,
      };
    }

    const match = evaluateRepoRule(rule, pr, 'opened');
    if (!match.matched) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_filtered',
        reason: match.reason,
      };
    }
    const nextGen = (existingGroup?.lifecycleGeneration ?? 1) + 1;
    return this.handleGroupTrigger(rule, pr, 'opened', dryRun, nextGen, guard);
  }

  private async checkAndRecordCreationQuota(repoKey: string): Promise<boolean> {
    const limit = this.config.service.maxGroupCreatesPerRepoPerHour;
    const cutoff = this.now() - 3_600_000;
    return this.stateStore.update(s => {
      const repoState = s.repos[repoKey] ?? { knownPrs: {} };
      const recent = (repoState.recentCreations ?? []).filter(ts => ts > cutoff);
      if (recent.length >= limit) {
        repoState.recentCreations = recent;
        s.repos[repoKey] = repoState;
        return false;
      }
      recent.push(this.now());
      repoState.recentCreations = recent;
      s.repos[repoKey] = repoState;
      return true;
    });
  }

  private async handleGroupTrigger(
    rule: RepoRule,
    pr: PullRequestInfo,
    eventKind: EventKind,
    dryRun: boolean,
    generationOverride?: number,
    guard?: GenerationGuard,
  ): Promise<SyncActionPreview> {
    this.assertGenerationCurrent(guard);
    const prKey = makePrKey(rule.repo, pr.number);
    const repoKey = normalizeRepoKey(rule.repo);
    const state = await this.stateStore.load();
    this.assertGenerationCurrent(guard);

    const existingGroup = state.prGroups[prKey];
    const generation = generationOverride ?? existingGroup?.lifecycleGeneration ?? 1;
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, eventKind, generation);

    if (isPrGroupComplete(existingGroup, rule)) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'group_already_active',
        chatId: existingGroup!.chatId,
      };
    }

    const incompleteExisting = Boolean(existingGroup && !isPrGroupComplete(existingGroup, rule));
    if (
      eventKind !== 'manual_open' &&
      !incompleteExisting &&
      Object.hasOwn(state.processedEvents, dedupKey)
    ) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'event_already_processed',
      };
    }

    const groupName = renderSafeGroupName(rule.groupNameTemplate, pr);
    if (dryRun) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: incompleteExisting ? 'resume_group' : 'create_group',
        groupName,
        ...(existingGroup?.chatId ? { chatId: existingGroup.chatId } : {}),
      };
    }

    if (!existingGroup && eventKind !== 'manual_open') {
      const allowed = await this.checkAndRecordCreationQuota(repoKey);
      this.assertGenerationCurrent(guard);
      if (!allowed) {
        await this.stateStore.appendEvent({
          level: 'warn',
          kind: 'group_creation_rate_capped',
          repo: rule.repo,
          prNumber: pr.number,
          message: `Skipped group creation for ${prKey}: hourly cap (${this.config.service.maxGroupCreatesPerRepoPerHour}) reached`,
        });
        return {
          repo: rule.repo,
          prNumber: pr.number,
          action: 'skip_rate_limited',
          reason: 'hourly_group_creation_cap',
        };
      }
    }

    this.assertGenerationCurrent(guard);
    const { github, bridge } = this.ensureClients(state.rateLimits);
    const result = await bridge.ensurePrReviewGroup({
      rule,
      pr,
      githubClient: github,
    });

    const finalGen = result.record.lifecycleGeneration ?? generation;
    await this.stateStore.markEventProcessed(rule.repo, pr.number, pr.headSha, eventKind, finalGen);
    return {
      repo: rule.repo,
      prNumber: pr.number,
      action: result.reusedExisting ? 'resume_group' : 'create_group',
      chatId: result.record.chatId,
      groupName: result.record.groupName,
    };
  }

  private async handleNewCommit(
    rule: RepoRule,
    pr: PullRequestInfo,
    previousHeadSha: string,
    dryRun: boolean,
    guard?: GenerationGuard,
  ): Promise<SyncActionPreview> {
    this.assertGenerationCurrent(guard);
    if (previousHeadSha === pr.headSha) {
      return { repo: rule.repo, prNumber: pr.number, action: 'skip_dedup', reason: 'same_head_sha' };
    }
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    this.assertGenerationCurrent(guard);

    const group = state.prGroups[prKey];
    if (!group?.chatId || group.status !== 'active') {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_filtered',
        reason: 'no_active_group',
      };
    }

    const generation = group.lifecycleGeneration ?? 1;
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, 'new_commit', generation);
    if (Object.hasOwn(state.processedEvents, dedupKey)) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'commit_already_notified',
      };
    }

    if (dryRun) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'notify_new_commit',
        chatId: group.chatId,
      };
    }

    this.assertGenerationCurrent(guard);
    const { bridge } = this.ensureClients(state.rateLimits);
    const content = buildNewCommitMessage(pr, previousHeadSha);
    await bridge.sendFollowUpUpdate({
      creatorLarkAppId: group.creatorLarkAppId,
      chatId: group.chatId,
      dedupSeed: dedupKey,
      content,
    });

    await this.stateStore.update(s => {
      const g = s.prGroups[prKey];
      if (g) {
        g.lastHeadSha = pr.headSha;
        g.updatedAt = new Date(this.now()).toISOString();
      }
      Object.defineProperty(s.processedEvents, dedupKey, {
        value: new Date(this.now()).toISOString(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    });

    await this.stateStore.appendEvent({
      level: 'info',
      kind: 'pr_new_commit_notified',
      repo: rule.repo,
      prNumber: pr.number,
      chatId: group.chatId,
      message: `Notified group ${group.chatId} of new head ${pr.headSha.slice(0, 12)}`,
    });

    return {
      repo: rule.repo,
      prNumber: pr.number,
      action: 'notify_new_commit',
      chatId: group.chatId,
    };
  }

  /**
   * Handles PR closure with generation-scoped dedup AND idempotent `closed` state landing:
   * even if the close notification for this (headSha, generation) was already sent,
   * `prGroups[prKey].status` is ALWAYS persisted as `'closed'` so state never diverges.
   */
  private async handlePrClosed(
    rule: RepoRule,
    pr: PullRequestInfo,
    dryRun: boolean,
    guard?: GenerationGuard,
  ): Promise<SyncActionPreview> {
    this.assertGenerationCurrent(guard);
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    this.assertGenerationCurrent(guard);

    const group = state.prGroups[prKey];
    if (!group?.chatId) {
      if (group && !dryRun && group.status !== 'closed') {
        await this.markGroupClosedIdempotently(rule.repo, pr.number, pr.headSha, guard);
      }
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_filtered',
        reason: 'no_active_group',
      };
    }
    if (group.status === 'closed') {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'already_closed',
        chatId: group.chatId,
      };
    }

    const generation = group.lifecycleGeneration ?? 1;
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, 'pr_closed', generation);
    if (Object.hasOwn(state.processedEvents, dedupKey)) {
      if (!dryRun) {
        await this.markGroupClosedIdempotently(rule.repo, pr.number, pr.headSha, guard);
      }
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'close_already_notified',
        chatId: group.chatId,
      };
    }

    if (dryRun) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'notify_pr_closed',
        chatId: group.chatId,
      };
    }

    this.assertGenerationCurrent(guard);
    const { bridge } = this.ensureClients(state.rateLimits);
    const content = buildPrClosedMessage(pr);
    await bridge.sendFollowUpUpdate({
      creatorLarkAppId: group.creatorLarkAppId,
      chatId: group.chatId,
      dedupSeed: dedupKey,
      content,
    });

    await this.stateStore.update(s => {
      const g = s.prGroups[prKey];
      if (g) {
        g.status = 'closed';
        g.lastHeadSha = pr.headSha;
        g.updatedAt = new Date(this.now()).toISOString();
      }
      Object.defineProperty(s.processedEvents, dedupKey, {
        value: new Date(this.now()).toISOString(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    });

    await this.stateStore.appendEvent({
      level: 'info',
      kind: 'pr_closed_notified',
      repo: rule.repo,
      prNumber: pr.number,
      chatId: group.chatId,
      message: `Notified group ${group.chatId} that PR was ${pr.merged ? 'merged' : 'closed'}`,
    });

    return {
      repo: rule.repo,
      prNumber: pr.number,
      action: 'notify_pr_closed',
      chatId: group.chatId,
    };
  }

  /**
   * Authoritative repository poll:
   * - Captures `pollGen` + `AbortSignal` so hot-reloading active->dormant aborts
   *   in-flight pagination & prevents any post-dormant external calls or state writes.
   * - Validates multi-page repositories across all pages (including legacy state
   *   cold restart inference and 3+ pages).
   * - Syncs closed status for ALL non-closed groups (including `onPrClosed: false`
   *   and `creating`) and never advances ETag on ANY per-PR error or close failure.
   */
  async pollRepo(
    initialRule: RepoRule,
    opts?: { dryRun?: boolean; bypassEtag?: boolean; waitForInFlight?: boolean; allowDisabledDryRun?: boolean },
  ): Promise<SyncActionPreview[]> {
    const repoKey = normalizeRepoKey(initialRule.repo);
    const dryRun = opts?.dryRun === true;

    if (!dryRun) {
      while (true) {
        const existing = this.pollInFlight.get(repoKey);
        if (!existing) break;
        if (!opts?.waitForInFlight) {
          return [];
        }
        await existing.catch(() => {});
      }
    }

    // Re-resolve LIVE rule AFTER waiting for any in-flight poll so disabling the repo
    // during the wait immediately halts rather than using a stale rule snapshot!
    const liveRule = this.findRuleByRepo(repoKey);
    if (!liveRule) {
      return [];
    }
    if (!liveRule.enabled && !(dryRun && opts?.allowDisabledDryRun)) {
      return [];
    }
    const rule = liveRule;

    const pollGen = this.generation;
    const signal = this.generationAbort.signal;
    const pollGuard: GenerationGuard =
      dryRun && opts?.allowDisabledDryRun
        ? { gen: pollGen, signal }
        : { gen: pollGen, repoKey, signal };

    const runPoll = async (): Promise<SyncActionPreview[]> => {
      if (!this.isGenerationCurrent(pollGen, signal)) return [];

      const state = await this.stateStore.load();
      if (!this.isGenerationCurrent(pollGen, signal)) return [];

      const { github } = this.ensureClients(state.rateLimits);
      const [owner, repo] = rule.repo.split('/');
      if (!owner || !repo) {
        return [{ repo: rule.repo, action: 'error', reason: 'invalid_repo_slug' }];
      }

      const repoState = state.repos[repoKey] ?? { knownPrs: {} };
      const currentFilterHash = computeRuleFilterHash(rule);
      const filtersChanged = Boolean(
        repoState.filterHash && repoState.filterHash !== currentFilterHash,
      );
      const hasIncompleteGroups = Object.values(state.prGroups).some(
        g =>
          normalizeRepoKey(g.repo) === repoKey &&
          g.status !== 'closed' &&
          !isPrGroupComplete(g, rule),
      );

      // Infer previousPageCount from open knownPrs on legacy state.json lacking lastPageCount
      let inferredPageCount = repoState.lastPageCount;
      if (inferredPageCount === undefined) {
        const openKnownCount = Object.values(repoState.knownPrs ?? {}).filter(
          c => c.state === 'open',
        ).length;
        if (openKnownCount >= 100) {
          inferredPageCount = Math.floor(openKnownCount / 100) + 1;
        }
      }

      const useEtag =
        !dryRun &&
        !opts?.bypassEtag &&
        !filtersChanged &&
        !hasIncompleteGroups &&
        Boolean(repoState.baselineCapturedAt);

      let listRes;
      try {
        listRes = await github.listOpenPullRequests(owner, repo, {
          persistedEtag: useEtag ? repoState.etag : undefined,
          persistedEtagKey: useEtag ? repoState.etagKey : undefined,
          previousPageCount: inferredPageCount,
          bypassEtag: !useEtag,
          priority: 'core',
          signal,
        });
      } catch (err) {
        if (isAbortError(err) || !this.isGenerationCurrent(pollGen, signal)) {
          return [];
        }
        await this.persistRateLimits(pollGen);
        if (!this.isGenerationCurrent(pollGen, signal)) return [];
        if (err instanceof GitHubRateLimitPausedError) {
          if (!dryRun) {
            await this.stateStore.update(s => {
              if (!this.isGenerationCurrent(pollGen, signal)) return;
              const r = s.repos[repoKey] ?? { knownPrs: {} };
              r.lastPollAt = new Date(this.now()).toISOString();
              r.lastPollStatus = 'rate_limited';
              r.lastError = err.message;
              s.repos[repoKey] = r;
            });
          }
          return [{ repo: rule.repo, action: 'skip_rate_limited', reason: err.reason }];
        }
        const safeErr = formatSafeError(err, this.registry);
        if (!dryRun) {
          await this.stateStore.update(s => {
            if (!this.isGenerationCurrent(pollGen, signal)) return;
            const r = s.repos[repoKey] ?? { knownPrs: {} };
            r.lastPollAt = new Date(this.now()).toISOString();
            r.lastPollStatus = 'error';
            r.lastError = safeErr;
            s.repos[repoKey] = r;
          });
        }
        return [{ repo: rule.repo, action: 'error', reason: safeErr }];
      }

      if (!this.isGenerationCurrent(pollGen, signal)) return [];
      await this.persistRateLimits(pollGen);
      if (!this.isGenerationCurrent(pollGen, signal)) return [];

      if (listRes.notModified) {
        if (!dryRun) {
          await this.stateStore.update(s => {
            if (!this.isGenerationCurrent(pollGen, signal)) return;
            const r = s.repos[repoKey] ?? { knownPrs: {} };
            r.etag = listRes.etag ?? r.etag;
            r.etagKey = listRes.etagKey;
            r.lastPageCount = listRes.pageCount;
            r.lastPollAt = new Date(this.now()).toISOString();
            r.lastPollStatus = 'not_modified';
            delete r.lastError;
            s.repos[repoKey] = r;
          });
        }
        return [{ repo: rule.repo, action: 'skip_not_modified', reason: 'etag_304' }];
      }

      // FIRST-RUN BASELINE SNAPSHOT: capture all currently open PRs WITHOUT creating any groups!
      if (!repoState.baselineCapturedAt) {
        if (!this.isGenerationCurrent(pollGen, signal)) return [];
        if (listRes.truncated) {
          await this.stateStore.appendEvent({
            level: 'warn',
            kind: 'baseline_truncated_warning',
            repo: rule.repo,
            message: `Baseline snapshot hit pagination cap (${listRes.pulls.length} open PRs)`,
          });
        }
        const nowIso = new Date(this.now()).toISOString();
        if (!dryRun && this.isGenerationCurrent(pollGen, signal)) {
          await this.stateStore.update(s => {
            if (!this.isGenerationCurrent(pollGen, signal)) return;
            const knownPrs: Record<
              string,
              { headSha: string; draft: boolean; state: 'open' | 'closed'; updatedAt: string }
            > = {};
            for (const pr of listRes.pulls) {
              knownPrs[String(pr.number)] = {
                headSha: pr.headSha,
                draft: pr.draft,
                state: 'open',
                updatedAt: pr.updatedAt || nowIso,
              };
            }
            s.repos[repoKey] = {
              etag: listRes.etag,
              etagKey: listRes.etagKey,
              lastPageCount: listRes.pageCount,
              filterHash: currentFilterHash,
              baselineCapturedAt: nowIso,
              lastPollAt: nowIso,
              lastPollStatus: 'baseline',
              knownPrs,
            };
          });
          await this.stateStore.appendEvent({
            level: 'info',
            kind: 'baseline_captured',
            repo: rule.repo,
            message: `Captured initial baseline of ${listRes.pulls.length} open PR(s) without creating groups`,
          });
        }
        return [
          {
            repo: rule.repo,
            action: 'baseline_captured',
            reason: `captured_${listRes.pulls.length}_open_prs`,
          },
        ];
      }

      // Normal incremental poll after baseline
      const actions: SyncActionPreview[] = [];
      const failedPrNumbers = new Set<number>();
      const deferredPrNumbers = new Set<number>();
      let firstErrorReason: string | undefined;
      const openNumbers = new Set<number>();

      const runQueuedPr = async (
        prNumber: number,
        fn: (guard: GenerationGuard) => Promise<SyncActionPreview>,
      ): Promise<void> => {
        if (!this.isGenerationCurrent(pollGen, signal)) return;
        if (dryRun) {
          try {
            actions.push(await fn(pollGuard));
          } catch (err) {
            if (isAbortError(err) || !this.isGenerationCurrent(pollGen, signal)) return;
            throw err;
          }
          return;
        }
        const prKey = makePrKey(rule.repo, prNumber);
        try {
          const action = await this.queue.enqueue(prKey, async taskSignal => {
            const combinedGuard: GenerationGuard = { gen: pollGen, repoKey, signal: taskSignal };
            this.assertGenerationCurrent(combinedGuard);
            return fn(combinedGuard);
          });
          if (this.isGenerationCurrent(pollGen, signal)) {
            if (action.action === 'skip_rate_limited') {
              deferredPrNumbers.add(prNumber);
            }
            actions.push(action);
          }
        } catch (err) {
          if (isAbortError(err) || !this.isGenerationCurrent(pollGen, signal)) return;
          const reason = formatSafeError(err, this.registry);
          failedPrNumbers.add(prNumber);
          if (!firstErrorReason) firstErrorReason = reason;
          actions.push({ repo: rule.repo, prNumber, action: 'error', reason });
        }
      };

      for (const pr of listRes.pulls) {
        if (!this.isGenerationCurrent(pollGen, signal)) return [];
        openNumbers.add(pr.number);
        const prevCursor = repoState.knownPrs[String(pr.number)];
        const prKey = makePrKey(rule.repo, pr.number);
        const existingGroup = state.prGroups[prKey];

        // Case 0: Closed PR or closed group reopened!
        if (prevCursor?.state === 'closed' || existingGroup?.status === 'closed') {
          await runQueuedPr(pr.number, g => this.handlePrReopened(rule, pr, dryRun, g));
          continue;
        }

        // Case 1: Incomplete crash-interrupted or unfinished group -> resume immediately
        if (existingGroup && !isPrGroupComplete(existingGroup, rule)) {
          await runQueuedPr(pr.number, g =>
            this.handleGroupTrigger(rule, pr, 'opened', dryRun, undefined, g),
          );
          continue;
        }

        // Case 2: Newly discovered PR since baseline
        if (!prevCursor) {
          const match = evaluateRepoRule(rule, pr, 'opened');
          if (!match.matched) {
            actions.push({
              repo: rule.repo,
              prNumber: pr.number,
              action: 'skip_filtered',
              reason: match.reason,
            });
          } else {
            await runQueuedPr(pr.number, g =>
              this.handleGroupTrigger(rule, pr, 'opened', dryRun, undefined, g),
            );
          }
          continue;
        }

        // Case 3: Draft -> ready_for_review transition (even for baseline drafts!)
        if (prevCursor.draft && !pr.draft) {
          const match = evaluateRepoRule(rule, pr, 'ready_for_review');
          if (!match.matched) {
            actions.push({
              repo: rule.repo,
              prNumber: pr.number,
              action: 'skip_filtered',
              reason: match.reason,
            });
          } else {
            await runQueuedPr(pr.number, g =>
              this.handleGroupTrigger(rule, pr, 'ready_for_review', dryRun, undefined, g),
            );
          }
          continue;
        }

        // Case 4: Optional onNewCommit on already-active PR group
        if (
          rule.onNewCommit &&
          existingGroup?.status === 'active' &&
          existingGroup.lastHeadSha !== pr.headSha
        ) {
          await runQueuedPr(pr.number, g =>
            this.handleNewCommit(rule, pr, existingGroup.lastHeadSha, dryRun, g),
          );
        }
      }

      // Case 5: ALL non-closed groups missing from a non-truncated open PR scan
      // (keeps prGroups in sync even when onPrClosed is false or group was stuck in creating!)
      if (!listRes.truncated && this.isGenerationCurrent(pollGen, signal)) {
        for (const group of Object.values(state.prGroups)) {
          if (!this.isGenerationCurrent(pollGen, signal)) return [];
          if (
            normalizeRepoKey(group.repo) !== repoKey ||
            group.status === 'closed' ||
            openNumbers.has(group.prNumber)
          ) {
            continue;
          }
          try {
            const latestPr = await github.getPullRequest(owner, repo, group.prNumber, {
              priority: 'non_core',
              signal,
            });
            if (!this.isGenerationCurrent(pollGen, signal)) return [];
            if (latestPr.state === 'closed') {
              if (rule.onPrClosed && group.chatId && group.status === 'active') {
                await runQueuedPr(group.prNumber, g =>
                  this.handlePrClosed(rule, latestPr, dryRun, g),
                );
              } else if (!dryRun) {
                await this.markGroupClosedIdempotently(
                  rule.repo,
                  group.prNumber,
                  latestPr.headSha,
                  pollGuard,
                );
              }
            }
          } catch (err) {
            if (isAbortError(err) || !this.isGenerationCurrent(pollGen, signal)) return [];
            const reason = formatSafeError(err, this.registry);
            failedPrNumbers.add(group.prNumber);
            if (!firstErrorReason) firstErrorReason = reason;
            if (err instanceof GitHubRateLimitPausedError) {
              actions.push({
                repo: rule.repo,
                prNumber: group.prNumber,
                action: 'skip_rate_limited',
                reason: err.reason,
              });
            } else {
              actions.push({
                repo: rule.repo,
                prNumber: group.prNumber,
                action: 'error',
                reason,
              });
            }
          }
        }
      }

      if (!this.isGenerationCurrent(pollGen, signal)) return [];

      // Persist updated repo cursor & ETag ONLY cleanly:
      // If ANY PR task failed OR was deferred (e.g. hourly group-creation cap / rate limit),
      // DO NOT advance ETag and DO NOT mark those PRs in knownPrs so they retry cleanly!
      if (!dryRun) {
        const hadPrError = failedPrNumbers.size > 0;
        const hadDeferred = deferredPrNumbers.size > 0;
        const shouldHoldEtag = hadPrError || hadDeferred;
        const nowIso = new Date(this.now()).toISOString();
        if (shouldHoldEtag) {
          github.clearEtagCache();
        }
        await this.stateStore.update(s => {
          if (!this.isGenerationCurrent(pollGen, signal)) return;
          const r = s.repos[repoKey] ?? { knownPrs: {} };
          if (!shouldHoldEtag) {
            r.etag = listRes.etag;
            r.etagKey = listRes.etagKey;
            r.lastPageCount = listRes.pageCount;
            r.lastPollStatus = 'ok';
            delete r.lastError;
          } else {
            delete r.etag;
            delete r.etagKey;
            r.lastPageCount = listRes.pageCount;
            if (hadPrError) {
              r.lastPollStatus = 'error';
              r.lastError = firstErrorReason ?? 'one or more PR actions failed';
            } else {
              r.lastPollStatus = 'rate_limited';
              r.lastError = 'deferred PR(s) pending hourly group creation cap or rate limit';
            }
          }
          r.filterHash = currentFilterHash;
          r.lastPollAt = nowIso;

          const nextKnown: typeof r.knownPrs = { ...r.knownPrs };
          for (const pr of listRes.pulls) {
            if (failedPrNumbers.has(pr.number) || deferredPrNumbers.has(pr.number)) continue;
            nextKnown[String(pr.number)] = {
              headSha: pr.headSha,
              draft: pr.draft,
              state: 'open',
              updatedAt: pr.updatedAt || nowIso,
            };
          }
          if (!listRes.truncated) {
            for (const [numStr, cur] of Object.entries(nextKnown)) {
              const num = Number(numStr);
              if (
                !openNumbers.has(num) &&
                !failedPrNumbers.has(num) &&
                !deferredPrNumbers.has(num) &&
                cur.state === 'open'
              ) {
                nextKnown[numStr] = { ...cur, state: 'closed', updatedAt: nowIso };
              }
            }
          }
          r.knownPrs = nextKnown;
          s.repos[repoKey] = r;
        });
      }

      return actions;
    };

    if (dryRun) {
      return runPoll();
    }

    const promise = runPoll().finally(() => {
      if (this.pollInFlight.get(repoKey) === promise) {
        this.pollInFlight.delete(repoKey);
      }
    });
    this.pollInFlight.set(repoKey, promise);
    return promise;
  }

  async sync(opts?: { repo?: string; dryRun?: boolean }): Promise<SyncResult> {
    const dryRun = opts?.dryRun === true;
    const syncGen = this.generation;
    const initialRepoKeys = opts?.repo
      ? [normalizeRepoKey(opts.repo)]
      : this.getEnabledRules().map(r => normalizeRepoKey(r.repo));

    if (opts?.repo && !this.findRuleByRepo(opts.repo)) {
      return {
        ok: false,
        dryRun,
        mode: this.getMode(),
        actions: [],
        errors: [`No configured rule found for repository "${opts.repo}"`],
      };
    }
    if (initialRepoKeys.length === 0) {
      return {
        ok: true,
        dryRun,
        mode: this.getMode(),
        actions: [],
        errors: [],
      };
    }

    const actions: SyncActionPreview[] = [];
    const errors: string[] = [];

    for (const repoKey of initialRepoKeys) {
      // Re-resolve current rule & enabled state BEFORE every repo iteration (never reuse stale snapshots!)
      const liveRule = this.findRuleByRepo(repoKey);
      if (!liveRule) continue;
      if (!liveRule.enabled && !(dryRun && opts?.repo)) continue;
      if (!opts?.repo && this.generation !== syncGen && this.getEnabledRules().length === 0) {
        break;
      }

      try {
        const repoActions = await this.pollRepo(liveRule, {
          dryRun,
          bypassEtag: dryRun,
          waitForInFlight: true,
          allowDisabledDryRun: Boolean(opts?.repo),
        });
        actions.push(...repoActions);
        for (const a of repoActions) {
          if (a.action === 'error' && a.reason) {
            errors.push(`${liveRule.repo}: ${a.reason}`);
          }
        }
      } catch (err) {
        errors.push(`${liveRule.repo}: ${formatSafeError(err, this.registry)}`);
      }
    }

    return {
      ok: errors.length === 0,
      dryRun,
      mode: this.getMode(),
      actions,
      errors,
    };
  }

  /**
   * Explicit manual PR trigger (`github:open-pr owner/repo#N [--dry-run]` or Dashboard action).
   * Explicitly allowed to backfill pre-existing baseline PRs AND resume incomplete
   * groups (e.g. unverified kickoff or unset top notice) without creating a duplicate group!
   */
  async openPr(opts: {
    repo: string;
    prNumber: number;
    dryRun?: boolean;
  }): Promise<OpenPrResult> {
    const dryRun = opts.dryRun === true;
    let canonicalRepo: string;
    try {
      canonicalRepo = validateRepoSlug(opts.repo);
    } catch (err) {
      return {
        ok: false,
        dryRun,
        repo: opts.repo,
        prNumber: opts.prNumber,
        action: 'error',
        error: formatSafeError(err, this.registry),
      };
    }

    if (!Number.isSafeInteger(opts.prNumber) || opts.prNumber < 1) {
      return {
        ok: false,
        dryRun,
        repo: canonicalRepo,
        prNumber: opts.prNumber,
        action: 'error',
        error: 'PR number must be a positive safe integer',
      };
    }

    const rule = this.findRuleByRepo(canonicalRepo);
    if (!rule) {
      return {
        ok: false,
        dryRun,
        repo: canonicalRepo,
        prNumber: opts.prNumber,
        action: 'error',
        error: `No repository rule configured for ${canonicalRepo}`,
      };
    }

    if (!rule.creatorBotAppId) {
      return {
        ok: false,
        dryRun,
        repo: canonicalRepo,
        prNumber: opts.prNumber,
        action: 'error',
        error: `Repository rule ${canonicalRepo} has no creatorBotAppId configured`,
      };
    }

    try {
      const state = await this.stateStore.load();
      const { github, bridge } = this.ensureClients(state.rateLimits);
      const [owner, repo] = canonicalRepo.split('/');
      const pr = await github.getPullRequest(owner!, repo!, opts.prNumber, {
        priority: 'core',
        bypassPauseCheck: true,
      });
      await this.persistRateLimits();

      const prKey = makePrKey(rule.repo, pr.number);
      const repoKey = normalizeRepoKey(rule.repo);
      const existing = state.prGroups[prKey];
      const groupName = renderSafeGroupName(rule.groupNameTemplate, pr);

      if (isPrGroupComplete(existing, rule)) {
        return {
          ok: true,
          dryRun,
          repo: rule.repo,
          prNumber: pr.number,
          action: 'already_active',
          chatId: existing!.chatId,
          shareLink: existing!.shareLink ?? null,
          kickoffMessageId: existing!.kickoffMessageId ?? null,
          kickoffVerified: existing!.kickoffVerified,
          topNoticeSet: existing!.topNoticeSet,
          shareLinkPosted: existing!.shareLinkPosted,
          groupName: existing!.groupName,
        };
      }

      if (dryRun) {
        return {
          ok: true,
          dryRun: true,
          repo: rule.repo,
          prNumber: pr.number,
          action: existing ? 'would_resume' : 'would_create',
          ...(existing?.chatId ? { chatId: existing.chatId } : {}),
          groupName,
          kickoffPreview: buildKickoffPrompt(rule.kickoffPromptTemplate, pr),
        };
      }

      return await this.queue.enqueue<OpenPrResult>(prKey, async () => {
        const orchestrated = await bridge.ensurePrReviewGroup({
          rule,
          pr,
          githubClient: github,
        });
        const finalGen = orchestrated.record.lifecycleGeneration ?? 1;
        await this.stateStore.markEventProcessed(
          rule.repo,
          pr.number,
          pr.headSha,
          'manual_open',
          finalGen,
        );
        // Sync knownPrs & invalidate repo ETag so subsequent polls do not get a stale 304
        // or spuriously re-trigger reopen on a reactivated PR!
        await this.stateStore.update(s => {
          const r = s.repos[repoKey] ?? { knownPrs: {} };
          r.knownPrs[String(pr.number)] = {
            headSha: pr.headSha,
            draft: pr.draft,
            state: pr.state,
            updatedAt: pr.updatedAt || new Date(this.now()).toISOString(),
          };
          delete r.etag;
          delete r.etagKey;
          s.repos[repoKey] = r;
        });
        this.githubClient?.clearEtagCache();

        return {
          ok: true,
          dryRun: false,
          repo: rule.repo,
          prNumber: pr.number,
          action: orchestrated.reusedExisting ? 'resumed' : 'created',
          chatId: orchestrated.record.chatId,
          shareLink: orchestrated.record.shareLink ?? null,
          kickoffMessageId: orchestrated.record.kickoffMessageId ?? null,
          kickoffVerified: orchestrated.record.kickoffVerified,
          topNoticeSet: orchestrated.record.topNoticeSet,
          shareLinkPosted: orchestrated.record.shareLinkPosted,
          groupName: orchestrated.record.groupName,
        };
      });
    } catch (err) {
      return {
        ok: false,
        dryRun,
        repo: canonicalRepo,
        prNumber: opts.prNumber,
        action: 'error',
        error: formatSafeError(err, this.registry),
      };
    }
  }

  async testAuth(opts?: { repo?: string; timeoutMs?: number }): Promise<AuthTestResult> {
    const state = await this.stateStore.load();
    const { github } = this.ensureClients(state.rateLimits);
    const res = await github.testAuth(opts);
    await this.persistRateLimits();
    return res;
  }
}
