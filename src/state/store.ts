import { join, resolve } from 'node:path';
import type {
  EventKind,
  EventLogEntry,
  PluginState,
  PrGroupRecord,
  RateLimitState,
  RepoRuntimeState,
} from '../types.ts';
import {
  acquireSecureLock,
  appendSecureJsonl,
  ensureSecureDir,
  readSecureFileIfExists,
  writeSecureFileAtomic,
} from '../security/fs.ts';
import { SecretRegistry, defaultSecretRegistry } from '../security/redact.ts';

const MAX_STATE_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_PROCESSED_EVENTS = 10_000;
const MAX_PROCESSED_DELIVERIES = 5_000;
const DELIVERY_TTL_MS = 72 * 60 * 60 * 1000; // 72 hours
const MAX_EVENT_LOG_BYTES = 5 * 1024 * 1024; // 5 MiB

export class StateCorruptError extends Error {
  readonly code = 'STATE_CORRUPT';
  readonly statePath: string;
  constructor(statePath: string, detail: string) {
    super(`Corrupt state file at ${statePath}: ${detail} (refusing to overwrite)`);
    this.name = 'StateCorruptError';
    this.statePath = statePath;
  }
}

export function createEmptyState(): PluginState {
  return {
    schemaVersion: 1,
    repos: {},
    prGroups: {},
    processedEvents: {},
    processedDeliveries: {},
    rateLimits: {},
    service: {
      mode: 'dormant',
      activeRepoCount: 0,
    },
  };
}

export function makePrKey(repo: string, prNumber: number): string {
  return `${repo.trim().toLowerCase()}#${prNumber}`;
}

export function makeEventDedupKey(
  repo: string,
  prNumber: number,
  headSha: string,
  eventKind: EventKind,
  generation = 1,
): string {
  const gen = Number.isInteger(generation) && generation >= 1 ? generation : 1;
  return `${repo.trim().toLowerCase()}#${prNumber}@${headSha.trim().toLowerCase()}:${eventKind}:g${gen}`;
}

function pruneMapByTimestamp(map: Record<string, string>, maxEntries: number, minTsMs?: number): void {
  const entries = Object.entries(map);
  if (minTsMs !== undefined) {
    for (const [k, ts] of entries) {
      const parsed = Date.parse(ts);
      if (Number.isNaN(parsed) || parsed < minTsMs) {
        delete map[k];
      }
    }
  }
  const remaining = Object.entries(map);
  if (remaining.length <= maxEntries) return;
  remaining.sort((a, b) => Date.parse(a[1]) - Date.parse(b[1]));
  const toDrop = remaining.length - maxEntries;
  for (let i = 0; i < toDrop; i++) {
    const key = remaining[i]?.[0];
    if (key) delete map[key];
  }
}

function toSafeStringRecord(
  raw: Record<string, unknown> | undefined,
  statePath: string,
  fieldName: string,
): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  if (!raw) return out;
  for (const [k, v] of Object.entries(raw)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
      throw new StateCorruptError(statePath, `forbidden key "${k}" inside "${fieldName}"`);
    }
    if (typeof v !== 'string') {
      throw new StateCorruptError(
        statePath,
        `entry "${fieldName}[${k}]" must be a string (got ${typeof v})`,
      );
    }
    out[k] = v;
  }
  return out;
}

function assertStateMapField(
  statePath: string,
  val: unknown,
  fieldName: string,
): Record<string, unknown> | undefined {
  if (val === undefined) return undefined;
  if (!val || typeof val !== 'object' || Array.isArray(val)) {
    throw new StateCorruptError(statePath, `field "${fieldName}" must be a JSON object`);
  }
  return val as Record<string, unknown>;
}

function normalizeState(raw: unknown, statePath: string): PluginState {
  const base = createEmptyState();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new StateCorruptError(statePath, 'root JSON value must be an object');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.schemaVersion !== undefined && obj.schemaVersion !== 1) {
    throw new StateCorruptError(
      statePath,
      `unsupported schemaVersion: ${String(obj.schemaVersion)}`,
    );
  }

  const repos = assertStateMapField(statePath, obj.repos, 'repos');
  if (repos) {
    for (const [repoKey, entry] of Object.entries(repos)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new StateCorruptError(statePath, `entry "repos[${repoKey}]" must be an object`);
      }
      const rec = entry as Record<string, unknown>;
      if (rec.knownPrs !== undefined) {
        assertStateMapField(statePath, rec.knownPrs, `repos[${repoKey}].knownPrs`);
      }
    }
    base.repos = repos as Record<string, RepoRuntimeState>;
  }

  const prGroups = assertStateMapField(statePath, obj.prGroups, 'prGroups');
  if (prGroups) {
    for (const [prKey, entry] of Object.entries(prGroups)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new StateCorruptError(statePath, `entry "prGroups[${prKey}]" must be an object`);
      }
    }
    base.prGroups = prGroups as Record<string, PrGroupRecord>;
  }

  const processedEvents = assertStateMapField(statePath, obj.processedEvents, 'processedEvents');
  base.processedEvents = toSafeStringRecord(processedEvents, statePath, 'processedEvents');

  const processedDeliveries = assertStateMapField(
    statePath,
    obj.processedDeliveries,
    'processedDeliveries',
  );
  base.processedDeliveries = toSafeStringRecord(
    processedDeliveries,
    statePath,
    'processedDeliveries',
  );

  const rateLimits = assertStateMapField(statePath, obj.rateLimits, 'rateLimits');
  if (rateLimits) base.rateLimits = rateLimits as RateLimitState;

  const svcObj = assertStateMapField(statePath, obj.service, 'service');
  if (svcObj) {
    if (
      svcObj.mode !== undefined &&
      svcObj.mode !== 'dormant' &&
      svcObj.mode !== 'active' &&
      svcObj.mode !== 'paused'
    ) {
      throw new StateCorruptError(statePath, `invalid service.mode: ${String(svcObj.mode)}`);
    }
    if (
      svcObj.activeRepoCount !== undefined &&
      (typeof svcObj.activeRepoCount !== 'number' || !Number.isInteger(svcObj.activeRepoCount))
    ) {
      throw new StateCorruptError(statePath, 'service.activeRepoCount must be an integer');
    }
    if (
      svcObj.boundPort !== undefined &&
      (typeof svcObj.boundPort !== 'number' || !Number.isInteger(svcObj.boundPort))
    ) {
      throw new StateCorruptError(statePath, 'service.boundPort must be an integer');
    }
    if (
      svcObj.pid !== undefined &&
      (typeof svcObj.pid !== 'number' || !Number.isInteger(svcObj.pid))
    ) {
      throw new StateCorruptError(statePath, 'service.pid must be an integer');
    }
    for (const strKey of ['startedAt', 'lastHeartbeatAt', 'lastReloadAt'] as const) {
      if (svcObj[strKey] !== undefined && typeof svcObj[strKey] !== 'string') {
        throw new StateCorruptError(statePath, `service.${strKey} must be a string`);
      }
    }
    const svc = svcObj as Partial<PluginState['service']>;
    base.service = {
      mode: svc.mode ?? 'dormant',
      activeRepoCount: svc.activeRepoCount ?? 0,
      ...(svc.boundPort !== undefined ? { boundPort: svc.boundPort } : {}),
      ...(svc.pid !== undefined ? { pid: svc.pid } : {}),
      ...(svc.startedAt !== undefined ? { startedAt: svc.startedAt } : {}),
      ...(svc.lastHeartbeatAt !== undefined ? { lastHeartbeatAt: svc.lastHeartbeatAt } : {}),
      ...(svc.lastReloadAt !== undefined ? { lastReloadAt: svc.lastReloadAt } : {}),
    };
  }
  return base;
}

export class StateStore {
  readonly pluginHome: string;
  readonly statePath: string;
  readonly stateLockPath: string;
  readonly eventLogPath: string;
  readonly eventLockPath: string;
  private readonly registry: SecretRegistry;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(pluginHome: string, registry: SecretRegistry = defaultSecretRegistry) {
    this.pluginHome = resolve(pluginHome);
    this.statePath = join(this.pluginHome, 'state.json');
    this.stateLockPath = join(this.pluginHome, '.state.lock');
    this.eventLogPath = join(this.pluginHome, 'events.jsonl');
    this.eventLockPath = join(this.pluginHome, '.events.lock');
    this.registry = registry;
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * Loads state.json strictly:
   * - Returns empty state ONLY when state.json does not exist (ENOENT).
   * - Fails closed with StateCorruptError when state.json exists but is malformed
   *   or non-object JSON, so existing dedup/group mappings are NEVER silently wiped!
   */
  async load(): Promise<PluginState> {
    const buf = await readSecureFileIfExists(this.statePath, {
      maxBytes: MAX_STATE_BYTES,
      requireMode0600: true,
    });
    if (!buf) return createEmptyState();
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString('utf8'));
    } catch (err) {
      throw new StateCorruptError(
        this.statePath,
        err instanceof Error ? err.message : 'invalid JSON',
      );
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new StateCorruptError(this.statePath, 'root JSON value must be an object');
    }
    return normalizeState(parsed, this.statePath);
  }

  /**
   * Atomically reads, mutates, validates secret-free, and persists state.json
   * under both an in-process serialization queue and cross-process file lock.
   */
  update<T>(mutator: (state: PluginState) => T | Promise<T>): Promise<T> {
    return this.enqueue(async () => {
      await ensureSecureDir(this.pluginHome);
      const lock = await acquireSecureLock(this.stateLockPath);
      try {
        const state = await this.load();
        const result = await mutator(state);

        // Enforce bounded dedup stores before persisting.
        pruneMapByTimestamp(state.processedEvents, MAX_PROCESSED_EVENTS);
        pruneMapByTimestamp(
          state.processedDeliveries,
          MAX_PROCESSED_DELIVERIES,
          Date.now() - DELIVERY_TTL_MS,
        );

        const sanitized = this.registry.redactUnknown(state) as PluginState;
        const serialized = `${JSON.stringify(sanitized, null, 2)}\n`;
        this.registry.assertNoSecrets(serialized);
        await writeSecureFileAtomic(this.statePath, serialized);
        return result;
      } finally {
        await lock.release();
      }
    });
  }

  async appendEvent(entry: Omit<EventLogEntry, 'ts'> & { ts?: string }): Promise<void> {
    const full: EventLogEntry = {
      ts: entry.ts ?? new Date().toISOString(),
      level: entry.level,
      kind: entry.kind,
      ...(entry.repo ? { repo: entry.repo } : {}),
      ...(entry.prNumber !== undefined ? { prNumber: entry.prNumber } : {}),
      ...(entry.chatId ? { chatId: entry.chatId } : {}),
      message: this.registry.redactString(entry.message),
      ...(entry.details
        ? { details: this.registry.redactUnknown(entry.details) as Record<string, unknown> }
        : {}),
    };
    const line = JSON.stringify(full);
    await appendSecureJsonl(this.eventLogPath, line, {
      maxBytes: MAX_EVENT_LOG_BYTES,
      maxBackups: 3,
      lockPath: this.eventLockPath,
    });
  }

  async readRecentEvents(limit = 50): Promise<EventLogEntry[]> {
    const buf = await readSecureFileIfExists(this.eventLogPath, {
      maxBytes: MAX_EVENT_LOG_BYTES + 1024 * 1024,
      requireMode0600: false,
    });
    if (!buf) return [];
    const lines = buf.toString('utf8').trim().split('\n').filter(Boolean);
    const tail = lines.slice(-Math.max(1, limit));
    const parsed: EventLogEntry[] = [];
    for (const line of tail) {
      try {
        parsed.push(JSON.parse(line) as EventLogEntry);
      } catch {
        // Ignore malformed trailing line
      }
    }
    return parsed.reverse();
  }

  async hasProcessedEvent(
    repo: string,
    prNumber: number,
    headSha: string,
    eventKind: EventKind,
    generation = 1,
  ): Promise<boolean> {
    const state = await this.load();
    const key = makeEventDedupKey(repo, prNumber, headSha, eventKind, generation);
    return Object.hasOwn(state.processedEvents, key);
  }

  async markEventProcessed(
    repo: string,
    prNumber: number,
    headSha: string,
    eventKind: EventKind,
    generation = 1,
  ): Promise<void> {
    const key = makeEventDedupKey(repo, prNumber, headSha, eventKind, generation);
    await this.update(state => {
      Object.defineProperty(state.processedEvents, key, {
        value: new Date().toISOString(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    });
  }

  async hasProcessedDelivery(deliveryId: string): Promise<boolean> {
    if (deliveryId === '__proto__' || deliveryId === 'constructor' || deliveryId === 'prototype') {
      return false;
    }
    const state = await this.load();
    if (!Object.hasOwn(state.processedDeliveries, deliveryId)) return false;
    const ts = state.processedDeliveries[deliveryId];
    if (!ts) return false;
    const age = Date.now() - Date.parse(ts);
    return !Number.isNaN(age) && age <= DELIVERY_TTL_MS;
  }

  async recordDelivery(deliveryId: string): Promise<boolean> {
    if (deliveryId === '__proto__' || deliveryId === 'constructor' || deliveryId === 'prototype') {
      return false;
    }
    return this.update(state => {
      const existing = Object.hasOwn(state.processedDeliveries, deliveryId)
        ? state.processedDeliveries[deliveryId]
        : undefined;
      if (existing && Date.now() - Date.parse(existing) <= DELIVERY_TTL_MS) {
        return false;
      }
      Object.defineProperty(state.processedDeliveries, deliveryId, {
        value: new Date().toISOString(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      return true;
    });
  }
}
