export class QueueDrainingError extends Error {
  readonly code = 'QUEUE_DRAINING';
  constructor(message = 'Per-PR queue is shutting down') {
    super(message);
    this.name = 'QueueDrainingError';
  }
}

export class QueueFullError extends Error {
  readonly code = 'QUEUE_FULL';
  constructor(key: string) {
    super(`Per-PR queue limit reached for ${key}`);
    this.name = 'QueueFullError';
  }
}

interface QueuedEntry<T = unknown> {
  run: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
}

/**
 * Per-PR strict FIFO serial execution queue with bounded global concurrency.
 * - Guarantees at most ONE task runs concurrently for any given PR key (`owner/repo#N`).
 * - Preserves EVERY enqueued task in FIFO order (never silently drops/overwrites callbacks).
 * - Returns a Promise per enqueue() that ALWAYS settles (including rejecting pending items
 *   cleanly on drain()/shutdown so callers never deadlock and delivery dedup never leaks).
 */
export class PerPrSerialQueue {
  private readonly maxConcurrency: number;
  private readonly maxPendingPerKey: number;
  private readonly active = new Set<string>();
  private readonly readyKeys: string[] = [];
  private readonly readySet = new Set<string>();
  private readonly perKeyQueues = new Map<string, QueuedEntry[]>();
  private runningCount = 0;
  private stopping = false;
  private drainResolvers: Array<() => void> = [];
  private readonly onError?: (key: string, err: unknown) => void;

  constructor(opts?: {
    maxConcurrency?: number;
    maxPendingPerKey?: number;
    onError?: (key: string, err: unknown) => void;
  }) {
    this.maxConcurrency = Math.max(1, Math.min(opts?.maxConcurrency ?? 4, 16));
    this.maxPendingPerKey = Math.max(1, Math.min(opts?.maxPendingPerKey ?? 32, 256));
    this.onError = opts?.onError;
  }

  isStopping(): boolean {
    return this.stopping;
  }

  enqueue<T>(key: string, run: () => Promise<T>): Promise<T> {
    if (this.stopping) {
      return Promise.reject(new QueueDrainingError());
    }

    let list = this.perKeyQueues.get(key);
    if (list && list.length >= this.maxPendingPerKey) {
      return Promise.reject(new QueueFullError(key));
    }

    return new Promise<T>((resolve, reject) => {
      if (!list) {
        list = [];
        this.perKeyQueues.set(key, list);
      }
      list.push({
        run: run as () => Promise<unknown>,
        resolve: resolve as (v: unknown) => void,
        reject,
      });

      if (!this.active.has(key) && !this.readySet.has(key)) {
        this.readySet.add(key);
        this.readyKeys.push(key);
      }
      this.pump();
    });
  }

  stats(): { active: number; queued: number; pending: number } {
    let pending = 0;
    for (const q of this.perKeyQueues.values()) {
      pending += q.length;
    }
    return {
      active: this.active.size,
      queued: this.readyKeys.length,
      pending,
    };
  }

  private pump(): void {
    while (!this.stopping && this.runningCount < this.maxConcurrency && this.readyKeys.length > 0) {
      const key = this.readyKeys.shift()!;
      this.readySet.delete(key);
      if (this.active.has(key)) continue;

      const list = this.perKeyQueues.get(key);
      const entry = list?.shift();
      if (!entry) {
        this.perKeyQueues.delete(key);
        continue;
      }
      if (list && list.length === 0) {
        this.perKeyQueues.delete(key);
      }

      this.active.add(key);
      this.runningCount++;
      void this.executeOne(key, entry);
    }

    if (this.runningCount === 0 && this.readyKeys.length === 0 && this.perKeyQueues.size === 0) {
      const resolvers = this.drainResolvers.splice(0);
      for (const r of resolvers) r();
    }
  }

  private async executeOne(key: string, entry: QueuedEntry): Promise<void> {
    try {
      const result = await entry.run();
      entry.resolve(result);
    } catch (err) {
      if (this.onError) {
        this.onError(key, err);
      }
      entry.reject(err);
    } finally {
      this.active.delete(key);
      this.runningCount--;

      const remaining = this.perKeyQueues.get(key);
      if (remaining && remaining.length > 0) {
        if (this.stopping) {
          this.perKeyQueues.delete(key);
          for (const item of remaining) {
            item.reject(new QueueDrainingError());
          }
        } else if (!this.readySet.has(key)) {
          this.readySet.add(key);
          this.readyKeys.push(key);
        }
      } else {
        this.perKeyQueues.delete(key);
      }

      this.pump();
    }
  }

  async drain(timeoutMs = 7_000): Promise<void> {
    this.stopping = true;
    this.readyKeys.length = 0;
    this.readySet.clear();

    // Reject all unstarted queued tasks immediately so awaiting callers never hang
    const err = new QueueDrainingError();
    for (const [, list] of this.perKeyQueues.entries()) {
      for (const item of list) {
        item.reject(err);
      }
    }
    this.perKeyQueues.clear();

    if (this.runningCount === 0) return;

    await new Promise<void>(resolvePromise => {
      const timer = setTimeout(() => {
        resolvePromise();
      }, timeoutMs);
      this.drainResolvers.push(() => {
        clearTimeout(timer);
        resolvePromise();
      });
    });
  }

  resetForRestart(): void {
    this.stopping = false;
  }
}
