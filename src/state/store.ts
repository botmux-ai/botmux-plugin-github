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
): string {
  return `${repo.trim().toLowerCase()}#${prNumber}@${headSha.trim().toLowerCase()}:${eventKind}`;
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

function toSafeStringRecord(raw: unknown): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (typeof v === 'string') {
      out[k] = v;
    }
  }
  return out;
}

function normalizeState(raw: unknown): PluginState {
  const base = createEmptyState();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return base;
  const obj = raw as Record<string, unknown>;
  if (obj.repos && typeof obj.repos === 'object' && !Array.isArray(obj.repos)) {
    base.repos = obj.repos as Record<string, RepoRuntimeState>;
  }
  if (obj.prGroups && typeof obj.prGroups === 'object' && !Array.isArray(obj.prGroups)) {
    base.prGroups = obj.prGroups as Record<string, PrGroupRecord>;
  }
  base.processedEvents = toSafeStringRecord(obj.processedEvents);
  base.processedDeliveries = toSafeStringRecord(obj.processedDeliveries);
  if (obj.rateLimits && typeof obj.rateLimits === 'object' && !Array.isArray(obj.rateLimits)) {
    base.rateLimits = obj.rateLimits as RateLimitState;
  }
  if (obj.service && typeof obj.service === 'object' && !Array.isArray(obj.service)) {
    const svc = obj.service as Partial<PluginState['service']>;
    base.service = {
      mode: svc.mode === 'active' || svc.mode === 'paused' ? svc.mode : 'dormant',
      activeRepoCount: typeof svc.activeRepoCount === 'number' ? svc.activeRepoCount : 0,
      ...(typeof svc.boundPort === 'number' && Number.isInteger(svc.boundPort)
        ? { boundPort: svc.boundPort }
        : {}),
      ...(typeof svc.pid === 'number' && Number.isInteger(svc.pid) ? { pid: svc.pid } : {}),
      ...(typeof svc.startedAt === 'string' ? { startedAt: svc.startedAt } : {}),
      ...(typeof svc.lastHeartbeatAt === 'string' ? { lastHeartbeatAt: svc.lastHeartbeatAt } : {}),
      ...(typeof svc.lastReloadAt === 'string' ? { lastReloadAt: svc.lastReloadAt } : {}),
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

  async load(): Promise<PluginState> {
    const buf = await readSecureFileIfExists(this.statePath, {
      maxBytes: MAX_STATE_BYTES,
      requireMode0600: true,
    });
    if (!buf) return createEmptyState();
    try {
      return normalizeState(JSON.parse(buf.toString('utf8')));
    } catch {
      return createEmptyState();
    }
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
  ): Promise<boolean> {
    const state = await this.load();
    const key = makeEventDedupKey(repo, prNumber, headSha, eventKind);
    return Object.hasOwn(state.processedEvents, key);
  }

  async markEventProcessed(
    repo: string,
    prNumber: number,
    headSha: string,
    eventKind: EventKind,
  ): Promise<void> {
    const key = makeEventDedupKey(repo, prNumber, headSha, eventKind);
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
