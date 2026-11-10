export interface SubscriptionDelayBatch {
  readonly done: Promise<void>;
  readonly cancelled: boolean;
  cancel(): Promise<void>;
}

interface MeasurementOperations<T> {
  start(): Promise<string>;
  measure(index: number, measurementId: string): Promise<T>;
  cancel(measurementId: string): Promise<void>;
  isCurrent(): boolean;
  onPending(index: number, pending: boolean): void;
  onResult(index: number, result: T): void;
}

/** One server-owned batch with the existing eight-worker rolling queue. */
export function createSubscriptionDelayBatch<T>(
  indexes: readonly number[],
  operations: MeasurementOperations<T>,
): SubscriptionDelayBatch {
  let cancelled = false;
  let stopped = false;
  const current = () => !stopped && operations.isCurrent();
  const start = Promise.resolve().then(() => operations.start());
  let released: Promise<void> | undefined;
  const release = () => released ??= start.then(
    (measurementId) => operations.cancel(measurementId),
    () => undefined,
  );
  const done = (async () => {
    try {
      const measurementId = await start;
      let next = 0;
      const worker = async () => {
        while (current() && next < indexes.length) {
          const index = indexes[next++];
          operations.onPending(index, true);
          try {
            const result = await operations.measure(index, measurementId);
            if (current()) operations.onResult(index, result);
          } finally {
            if (operations.isCurrent()) operations.onPending(index, false);
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(8, indexes.length) }, worker));
    } finally {
      stopped = true;
      await release();
    }
  })();
  return {
    done,
    get cancelled() { return cancelled; },
    async cancel() {
      cancelled = true;
      stopped = true;
      try {
        await release();
      } finally {
        await done.catch(() => {});
      }
    },
  };
}
