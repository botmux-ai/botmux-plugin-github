export class QueueDrainingError extends Error {
  readonly code = 'QUEUE_DRAINING';
  constructor(message = 'Per-PR queue is shutting down') {
    super(message);
    this.name = 'QueueDrainingError';
  }
}

export class QueueFullError extends Error {
  readonly code: 'QUEUE_KEY_FULL' | 'QUEUE_GLOBAL_FULL';
  constructor(code: 'QUEUE_KEY_FULL' | 'QUEUE_GLOBAL_FULL', message: string) {
    super(message);
    this.name = 'QueueFullError';
    this.code = code;
  }
}

export class QueueTaskTimeoutError extends Error {
  readonly code = 'QUEUE_TASK_TIMEOUT';
  constructor(key: string, timeoutMs: number) {
    super(`Per-PR task timed out after ${timeoutMs}ms for ${key}`);
    this.name = 'QueueTaskTimeoutError';
  }
}

interface QueuedEntry<T = unknown> {
  run: (signal: AbortSignal) => Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
}

export type TryEnqueueResult<T> =
  | { accepted: true; promise: Promise<T> }
  | { accepted: false; reason: 'draining' | 'key_full' | 'global_full' };

/**
 * Per-PR strict FIFO serial execution queue with bounded per-key AND global
 * pending caps plus cancellable per-task AbortSignal timeout.
 * - Guarantees at most ONE task runs concurrently for any given PR key (`owner/repo#N`)
 *   and never releases the key lock or concurrency slot until the running promise settles.
 * - Preserves EVERY accepted task in FIFO order (never silently drops/overwrites callbacks).
 * - Enforces both `maxPendingPerKey` and `maxGlobalPending` synchronously via `tryEnqueue()`
 *   so webhook admission can synchronously return HTTP 429/503 instead of a fake 202.
 */
export class PerPrSerialQueue {
  private readonly maxConcurrency: number;
  private readonly maxPendingPerKey: number;
  private readonly maxGlobalPending: number;
  private readonly taskTimeoutMs: number;
  private readonly active = new Set<string>();
  private readonly activeAborts = new Set<AbortController>();
  private readonly readyKeys: string[] = [];
  private readonly readySet = new Set<string>();
  private readonly perKeyQueues = new Map<string, QueuedEntry[]>();
  private totalPending = 0;
  private runningCount = 0;
  private stopping = false;
  private drainResolvers: Array<() => void> = [];
  private readonly onError?: (key: string, err: unknown) => void;

  constructor(opts?: {
    maxConcurrency?: number;
    maxPendingPerKey?: number;
    maxGlobalPending?: number;
    taskTimeoutMs?: number;
    onError?: (key: string, err: unknown) => void;
  }) {
    this.maxConcurrency = Math.max(1, Math.min(opts?.maxConcurrency ?? 4, 16));
    this.maxPendingPerKey = Math.max(1, Math.min(opts?.maxPendingPerKey ?? 32, 256));
    this.maxGlobalPending = Math.max(1, Math.min(opts?.maxGlobalPending ?? 256, 4096));
    this.taskTimeoutMs = Math.max(0, opts?.taskTimeoutMs ?? 120_000);
    this.onError = opts?.onError;
  }

  isStopping(): boolean {
    return this.stopping;
  }

  tryEnqueue<T>(key: string, run: (signal: AbortSignal) => Promise<T>): TryEnqueueResult<T> {
    if (this.stopping) {
      return { accepted: false, reason: 'draining' };
    }

    const existingList = this.perKeyQueues.get(key);
    if (existingList && existingList.length >= this.maxPendingPerKey) {
      return { accepted: false, reason: 'key_full' };
    }

    const willStartImmediately =
      !this.active.has(key) &&
      !this.readySet.has(key) &&
      this.runningCount < this.maxConcurrency &&
      this.readyKeys.length === 0;

    if (!willStartImmediately && this.totalPending >= this.maxGlobalPending) {
      return { accepted: false, reason: 'global_full' };
    }

    const promise = new Promise<T>((resolve, reject) => {
      let list = existingList;
      if (!list) {
        list = [];
        this.perKeyQueues.set(key, list);
      }
      list.push({
        run: run as (signal: AbortSignal) => Promise<unknown>,
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.totalPending++;

      if (!this.active.has(key) && !this.readySet.has(key)) {
        this.readySet.add(key);
        this.readyKeys.push(key);
      }
      this.pump();
    });

    return { accepted: true, promise };
  }

  enqueue<T>(key: string, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const res = this.tryEnqueue(key, run);
    if (res.accepted) return res.promise;
    if (res.reason === 'draining') {
      return Promise.reject(new QueueDrainingError());
    }
    if (res.reason === 'key_full') {
      return Promise.reject(
        new QueueFullError('QUEUE_KEY_FULL', `Per-PR queue limit reached for ${key}`),
      );
    }
    return Promise.reject(
      new QueueFullError('QUEUE_GLOBAL_FULL', `Global pending queue limit (${this.maxGlobalPending}) reached`),
    );
  }

  stats(): { active: number; queued: number; pending: number } {
    return {
      active: this.active.size,
      queued: this.readyKeys.length,
      pending: this.totalPending,
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
      this.totalPending = Math.max(0, this.totalPending - 1);
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

  private executeOne(key: string, entry: QueuedEntry): void {
    const controller = new AbortController();
    this.activeAborts.add(controller);

    let callerSettled = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

    const settleCallerOk = (val: unknown) => {
      if (callerSettled) return;
      callerSettled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      entry.resolve(val);
    };

    const settleCallerErr = (err: unknown) => {
      if (callerSettled) return;
      callerSettled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      if (this.onError) {
        this.onError(key, err);
      }
      entry.reject(err);
    };

    if (this.taskTimeoutMs > 0) {
      timeoutHandle = setTimeout(() => {
        controller.abort();
        settleCallerErr(new QueueTaskTimeoutError(key, this.taskTimeoutMs));
      }, this.taskTimeoutMs);
      timeoutHandle.unref?.();
    }

    // Wrap synchronously in Promise.resolve().then(...) so sync throws are captured too.
    const runPromise = Promise.resolve().then(() => entry.run(controller.signal));

    // Attach handlers directly to runPromise so it can NEVER trigger unhandledRejection,
    // AND keep `this.active` & `this.runningCount` locked until runPromise actually settles!
    runPromise.then(
      result => settleCallerOk(result),
      err => settleCallerErr(err),
    ).finally(() => {
      if (timeoutHandle) clearTimeout(timeoutHandle);
      this.activeAborts.delete(controller);
      this.active.delete(key);
      this.runningCount--;

      const remaining = this.perKeyQueues.get(key);
      if (remaining && remaining.length > 0) {
        if (this.stopping) {
          this.perKeyQueues.delete(key);
          this.totalPending = Math.max(0, this.totalPending - remaining.length);
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
    });
  }

  async drain(timeoutMs = 7_000): Promise<void> {
    this.stopping = true;
    this.readyKeys.length = 0;
    this.readySet.clear();

    const err = new QueueDrainingError();
    for (const [, list] of this.perKeyQueues.entries()) {
      for (const item of list) {
        item.reject(err);
      }
    }
    this.perKeyQueues.clear();
    this.totalPending = 0;

    if (this.runningCount === 0) return;

    await new Promise<void>(resolvePromise => {
      const timer = setTimeout(() => {
        for (const c of this.activeAborts) c.abort();
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
