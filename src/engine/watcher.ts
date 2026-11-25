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
import { HostBridge } from '../host/bridge.ts';
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
  now?: () => number;
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

    this.deliveryDedup = new DeliveryDedupCache({ now: this.now });
    this.queue = new PerPrSerialQueue({
      maxConcurrency: 4,
      onError: (key, err) => {
        void this.stateStore.appendEvent({
          level: 'error',
          kind: 'pr_queue_error',
          message: `Error processing ${key}: ${formatSafeError(err, this.registry)}`,
        });
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

  private ensureClients(initialRateLimits?: RateLimitState): {
    github: GitHubClient;
    bridge: HostBridge;
  } {
    // Register config secrets additively — NEVER clear the shared registry
    // (which also holds controlToken, hostBearerTokens, dashboardSecret, and larkAppSecrets).
    registerConfigSecrets(this.config, this.registry);

    if (!this.githubClient) {
      this.githubClient = new GitHubClient({
        auth: this.config.github,
        proxy: this.config.proxy,
        initialRateLimits,
        registry: this.registry,
        ghRunner: this.ghRunner,
        allowInsecureLocalForTests: this.allowInsecureLocalApiForTests,
        now: this.now,
      });
    }
    if (!this.hostBridge) {
      this.hostBridge = new HostBridge({
        stateStore: this.stateStore,
        discovery: this.discovery,
        proxy: this.config.proxy,
        registry: this.registry,
        larkClient: this.larkClient,
        cliExec: this.cliExec,
        now: this.now,
      });
    }
    return { github: this.githubClient, bridge: this.hostBridge };
  }

  /**
   * Starts the watcher:
   * - If ZERO enabled repo rules exist, strictly stays in DORMANT mode:
   *   ZERO GitHub API requests, ZERO Feishu/daemon calls, ZERO poll timers!
   * - If enabled repo rules exist, hydrates persisted state & starts per-repo timers.
   */
  async start(): Promise<void> {
    this.started = true;
    this.queue.resetForRestart();
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

  async reloadConfig(nextConfig: PluginConfig): Promise<ServiceMode> {
    this.clearTimers();
    this.config = nextConfig;
    this.githubClient = null;
    this.hostBridge = null;
    registerConfigSecrets(nextConfig, this.registry);

    const enabled = this.getEnabledRules();
    const state = await this.stateStore.load();
    const mode: ServiceMode = enabled.length === 0 ? 'dormant' : 'active';

    await this.stateStore.update(s => {
      s.service = {
        ...s.service,
        mode,
        activeRepoCount: enabled.length,
        lastReloadAt: new Date(this.now()).toISOString(),
        lastHeartbeatAt: new Date(this.now()).toISOString(),
      };
    });

    if (this.started && enabled.length > 0) {
      this.ensureClients(state.rateLimits);
      this.armPollTimers();
    }
    return mode;
  }

  async stop(drainTimeoutMs = 7_000): Promise<void> {
    this.started = false;
    this.clearTimers();
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
        void this.stateStore.appendEvent({
          level: 'error',
          kind: 'poll_error',
          repo: rule.repo,
          message: `Initial poll failed: ${formatSafeError(err, this.registry)}`,
        });
      });

      const timer = setInterval(() => {
        void this.pollRepo(rule, { dryRun: false, waitForInFlight: false }).catch(err => {
          void this.stateStore.appendEvent({
            level: 'error',
            kind: 'poll_error',
            repo: rule.repo,
            message: `Scheduled poll failed: ${formatSafeError(err, this.registry)}`,
          });
        });
      }, intervalMs);
      timer.unref?.();
      this.pollTimers.set(repoKey, timer);
    }
  }

  private async persistRateLimits(): Promise<void> {
    if (!this.githubClient) return;
    const snap = this.githubClient.rateLimits.snapshot();
    const mode = this.getMode();
    await this.stateStore.update(s => {
      s.rateLimits = snap;
      s.service.mode = mode;
      s.service.lastHeartbeatAt = new Date(this.now()).toISOString();
    });
  }

  private findRuleByRepo(repo: string): RepoRule | undefined {
    const target = normalizeRepoKey(repo);
    return this.config.repos.find(r => normalizeRepoKey(r.repo) === target);
  }

  /**
   * Handles a verified GitHub pull_request webhook event by feeding it into the
   * exact same FIFO per-PR serial queue used by the authoritative poller.
   */
  enqueueWebhookPrEvent(opts: {
    deliveryId: string;
    action: string;
    pr: PullRequestInfo;
  }): boolean {
    const rule = this.findRuleByRepo(opts.pr.repo);
    if (!rule || !rule.enabled || this.queue.isStopping()) {
      this.deliveryDedup.abort(opts.deliveryId);
      return false;
    }

    const prKey = makePrKey(rule.repo, opts.pr.number);
    const task = this.queue.enqueue(prKey, async () => {
      await this.processWebhookPrEvent(rule, opts.action, opts.pr);
      this.deliveryDedup.commit(opts.deliveryId);
      await this.stateStore.recordDelivery(opts.deliveryId);
    });

    // Guarantee deliveryDedup.abort on any rejection (including queue full/drain or processing error)
    task.catch(err => {
      this.deliveryDedup.abort(opts.deliveryId);
      void this.stateStore.appendEvent({
        level: 'error',
        kind: 'webhook_process_error',
        repo: rule.repo,
        prNumber: opts.pr.number,
        message: `Failed processing webhook ${opts.action}: ${formatSafeError(err, this.registry)}`,
      });
    });

    return true;
  }

  private async processWebhookPrEvent(
    rule: RepoRule,
    action: string,
    pr: PullRequestInfo,
  ): Promise<void> {
    const repoKey = normalizeRepoKey(rule.repo);
    const state = await this.stateStore.load();

    await this.stateStore.update(s => {
      const repoState = s.repos[repoKey] ?? { knownPrs: {} };
      repoState.knownPrs[String(pr.number)] = {
        headSha: pr.headSha,
        draft: pr.draft,
        state: pr.state,
        updatedAt: pr.updatedAt || new Date(this.now()).toISOString(),
      };
      s.repos[repoKey] = repoState;
    });

    if (action === 'opened' || action === 'ready_for_review' || action === 'reopened') {
      const triggerKind = action === 'ready_for_review' ? 'ready_for_review' : 'opened';
      const match = evaluateRepoRule(rule, pr, triggerKind);
      if (!match.matched) return;
      await this.handleGroupTrigger(rule, pr, triggerKind, false);
      return;
    }

    if (action === 'synchronize' && rule.onNewCommit) {
      const existingGroup = state.prGroups[makePrKey(rule.repo, pr.number)];
      if (existingGroup && existingGroup.status === 'active' && existingGroup.chatId) {
        await this.handleNewCommit(rule, pr, existingGroup.lastHeadSha, false);
      }
      return;
    }

    if (action === 'closed' && rule.onPrClosed) {
      const existingGroup = state.prGroups[makePrKey(rule.repo, pr.number)];
      if (existingGroup && existingGroup.status === 'active' && existingGroup.chatId) {
        await this.handlePrClosed(rule, pr, false);
      }
    }
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
  ): Promise<SyncActionPreview> {
    const prKey = makePrKey(rule.repo, pr.number);
    const repoKey = normalizeRepoKey(rule.repo);
    const state = await this.stateStore.load();
    const existingGroup = state.prGroups[prKey];
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, eventKind);

    if (existingGroup?.status === 'active' && existingGroup.chatId) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'group_already_active',
        chatId: existingGroup.chatId,
      };
    }

    if (
      eventKind !== 'manual_open' &&
      Object.hasOwn(state.processedEvents, dedupKey) &&
      existingGroup?.status !== 'creating'
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
        action: existingGroup?.status === 'creating' ? 'resume_group' : 'create_group',
        groupName,
        ...(existingGroup?.chatId ? { chatId: existingGroup.chatId } : {}),
      };
    }

    if (!existingGroup && eventKind !== 'manual_open') {
      const allowed = await this.checkAndRecordCreationQuota(repoKey);
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

    const { github, bridge } = this.ensureClients(state.rateLimits);
    const result = await bridge.ensurePrReviewGroup({
      rule,
      pr,
      githubClient: github,
    });

    await this.stateStore.markEventProcessed(rule.repo, pr.number, pr.headSha, eventKind);
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
  ): Promise<SyncActionPreview> {
    if (previousHeadSha === pr.headSha) {
      return { repo: rule.repo, prNumber: pr.number, action: 'skip_dedup', reason: 'same_head_sha' };
    }
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, 'new_commit');
    if (Object.hasOwn(state.processedEvents, dedupKey)) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'commit_already_notified',
      };
    }
    const group = state.prGroups[prKey];
    if (!group?.chatId || group.status !== 'active') {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_filtered',
        reason: 'no_active_group',
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

  private async handlePrClosed(
    rule: RepoRule,
    pr: PullRequestInfo,
    dryRun: boolean,
  ): Promise<SyncActionPreview> {
    const prKey = makePrKey(rule.repo, pr.number);
    const state = await this.stateStore.load();
    const dedupKey = makeEventDedupKey(rule.repo, pr.number, pr.headSha, 'pr_closed');
    if (Object.hasOwn(state.processedEvents, dedupKey)) {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_dedup',
        reason: 'close_already_notified',
      };
    }
    const group = state.prGroups[prKey];
    if (!group?.chatId || group.status !== 'active') {
      return {
        repo: rule.repo,
        prNumber: pr.number,
        action: 'skip_filtered',
        reason: 'no_active_group',
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
   * - Uses If-None-Match ETag (304 Not Modified consumes zero quota)
   * - First-run baseline capture snapshots ALL current open PRs without creating any groups!
   * - Never strands failed/creating PRs behind a 304 Not Modified ETag.
   */
  async pollRepo(
    rule: RepoRule,
    opts?: { dryRun?: boolean; bypassEtag?: boolean; waitForInFlight?: boolean },
  ): Promise<SyncActionPreview[]> {
    const repoKey = normalizeRepoKey(rule.repo);
    const dryRun = opts?.dryRun === true;

    if (!dryRun) {
      const existing = this.pollInFlight.get(repoKey);
      if (existing) {
        if (!opts?.waitForInFlight) {
          return [];
        }
        await existing.catch(() => {});
      }
    }

    const runPoll = async (): Promise<SyncActionPreview[]> => {
      const state = await this.stateStore.load();
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
      const hasCreatingGroups = Object.values(state.prGroups).some(
        g => normalizeRepoKey(g.repo) === repoKey && g.status === 'creating',
      );

      // Bypass ETag on dryRun, explicit bypassEtag, filter change, missing baseline,
      // OR when any crash-interrupted 'creating' group needs resumption!
      const useEtag =
        !dryRun &&
        !opts?.bypassEtag &&
        !filtersChanged &&
        !hasCreatingGroups &&
        Boolean(repoState.baselineCapturedAt);

      let listRes;
      try {
        listRes = await github.listOpenPullRequests(owner, repo, {
          persistedEtag: useEtag ? repoState.etag : undefined,
          persistedEtagKey: useEtag ? repoState.etagKey : undefined,
          bypassEtag: !useEtag,
          priority: 'core',
        });
      } catch (err) {
        await this.persistRateLimits();
        if (err instanceof GitHubRateLimitPausedError) {
          if (!dryRun) {
            await this.stateStore.update(s => {
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
            const r = s.repos[repoKey] ?? { knownPrs: {} };
            r.lastPollAt = new Date(this.now()).toISOString();
            r.lastPollStatus = 'error';
            r.lastError = safeErr;
            s.repos[repoKey] = r;
          });
        }
        return [{ repo: rule.repo, action: 'error', reason: safeErr }];
      }

      await this.persistRateLimits();

      if (listRes.notModified) {
        if (!dryRun) {
          await this.stateStore.update(s => {
            const r = s.repos[repoKey] ?? { knownPrs: {} };
            r.etag = listRes.etag ?? r.etag;
            r.etagKey = listRes.etagKey;
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
        if (listRes.truncated) {
          await this.stateStore.appendEvent({
            level: 'warn',
            kind: 'baseline_truncated_warning',
            repo: rule.repo,
            message: `Baseline snapshot hit pagination cap (${listRes.pulls.length} open PRs)`,
          });
        }
        const nowIso = new Date(this.now()).toISOString();
        if (!dryRun) {
          await this.stateStore.update(s => {
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
      let firstErrorReason: string | undefined;
      const openNumbers = new Set<number>();

      const runQueuedPr = async (
        prNumber: number,
        fn: () => Promise<SyncActionPreview>,
      ): Promise<void> => {
        if (dryRun) {
          actions.push(await fn());
          return;
        }
        const prKey = makePrKey(rule.repo, prNumber);
        try {
          const action = await this.queue.enqueue(prKey, fn);
          actions.push(action);
        } catch (err) {
          const reason = formatSafeError(err, this.registry);
          failedPrNumbers.add(prNumber);
          if (!firstErrorReason) firstErrorReason = reason;
          actions.push({ repo: rule.repo, prNumber, action: 'error', reason });
        }
      };

      for (const pr of listRes.pulls) {
        openNumbers.add(pr.number);
        const prevCursor = repoState.knownPrs[String(pr.number)];
        const prKey = makePrKey(rule.repo, pr.number);
        const existingGroup = state.prGroups[prKey];

        // Case 1: Incomplete crash-interrupted 'creating' group -> resume immediately
        if (existingGroup?.status === 'creating') {
          await runQueuedPr(pr.number, () => this.handleGroupTrigger(rule, pr, 'opened', dryRun));
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
            await runQueuedPr(pr.number, () =>
              this.handleGroupTrigger(rule, pr, 'opened', dryRun),
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
            await runQueuedPr(pr.number, () =>
              this.handleGroupTrigger(rule, pr, 'ready_for_review', dryRun),
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
          await runQueuedPr(pr.number, () =>
            this.handleNewCommit(rule, pr, existingGroup.lastHeadSha, dryRun),
          );
        }
      }

      // Case 5: Optional onPrClosed for active PR groups that vanished from a complete open PR scan
      if (rule.onPrClosed && !listRes.truncated) {
        for (const group of Object.values(state.prGroups)) {
          if (
            normalizeRepoKey(group.repo) !== repoKey ||
            group.status !== 'active' ||
            openNumbers.has(group.prNumber)
          ) {
            continue;
          }
          try {
            const latestPr = await github.getPullRequest(owner, repo, group.prNumber, {
              priority: 'non_core',
            });
            if (latestPr.state === 'closed') {
              await runQueuedPr(group.prNumber, () =>
                this.handlePrClosed(rule, latestPr, dryRun),
              );
            }
          } catch (err) {
            if (err instanceof GitHubRateLimitPausedError) {
              actions.push({
                repo: rule.repo,
                prNumber: group.prNumber,
                action: 'skip_rate_limited',
                reason: err.reason,
              });
            }
          }
        }
      }

      // Persist updated repo cursor & ETag ONLY cleanly:
      // If any PR task failed, do NOT advance ETag or record failed new PRs in knownPrs!
      if (!dryRun) {
        const hadPrError = failedPrNumbers.size > 0;
        const nowIso = new Date(this.now()).toISOString();
        if (hadPrError) {
          github.clearEtagCache();
        }
        await this.stateStore.update(s => {
          const r = s.repos[repoKey] ?? { knownPrs: {} };
          if (!hadPrError) {
            r.etag = listRes.etag;
            r.etagKey = listRes.etagKey;
            r.lastPollStatus = 'ok';
            delete r.lastError;
          } else {
            delete r.etag;
            delete r.etagKey;
            r.lastPollStatus = 'error';
            r.lastError = firstErrorReason ?? 'one or more PR actions failed';
          }
          r.filterHash = currentFilterHash;
          r.lastPollAt = nowIso;

          const nextKnown: typeof r.knownPrs = { ...r.knownPrs };
          for (const pr of listRes.pulls) {
            // Do not mark a newly failed PR as known so the next poll retries it!
            if (failedPrNumbers.has(pr.number)) continue;
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
              if (!openNumbers.has(num) && !failedPrNumbers.has(num) && cur.state === 'open') {
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
    const enabled = this.getEnabledRules();
    const targetRules = opts?.repo
      ? this.config.repos.filter(r => normalizeRepoKey(r.repo) === normalizeRepoKey(opts.repo!))
      : enabled;

    if (targetRules.length === 0) {
      return {
        ok: !opts?.repo,
        dryRun,
        mode: this.getMode(),
        actions: [],
        errors: opts?.repo ? [`No configured rule found for repository "${opts.repo}"`] : [],
      };
    }

    const actions: SyncActionPreview[] = [];
    const errors: string[] = [];

    for (const rule of targetRules) {
      try {
        const repoActions = await this.pollRepo(rule, {
          dryRun,
          bypassEtag: dryRun,
          waitForInFlight: true,
        });
        actions.push(...repoActions);
        for (const a of repoActions) {
          if (a.action === 'error' && a.reason) {
            errors.push(`${rule.repo}: ${a.reason}`);
          }
        }
      } catch (err) {
        errors.push(`${rule.repo}: ${formatSafeError(err, this.registry)}`);
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
   * Explicitly allowed to backfill pre-existing baseline PRs!
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

    if (!Number.isInteger(opts.prNumber) || opts.prNumber < 1) {
      return {
        ok: false,
        dryRun,
        repo: canonicalRepo,
        prNumber: opts.prNumber,
        action: 'error',
        error: 'PR number must be a positive integer',
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
      const existing = state.prGroups[prKey];
      const groupName = renderSafeGroupName(rule.groupNameTemplate, pr);

      if (existing?.status === 'active' && existing.chatId) {
        return {
          ok: true,
          dryRun,
          repo: rule.repo,
          prNumber: pr.number,
          action: 'already_active',
          chatId: existing.chatId,
          shareLink: existing.shareLink ?? null,
          kickoffMessageId: existing.kickoffMessageId ?? null,
          kickoffVerified: existing.kickoffVerified,
          topNoticeSet: existing.topNoticeSet,
          shareLinkPosted: existing.shareLinkPosted,
          groupName: existing.groupName,
        };
      }

      if (dryRun) {
        return {
          ok: true,
          dryRun: true,
          repo: rule.repo,
          prNumber: pr.number,
          action: existing?.status === 'creating' ? 'would_resume' : 'would_create',
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
        await this.stateStore.markEventProcessed(
          rule.repo,
          pr.number,
          pr.headSha,
          'manual_open',
        );
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
