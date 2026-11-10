import assert from "node:assert/strict";
import test from "node:test";
import { providerPrefix } from "../src/subscriptions.ts";
import { createSubscriptionDelayBatch } from "../src/subscriptionMeasurements.ts";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

const turn = () => new Promise<void>((resolve) => setImmediate(resolve));

test("delay batch keeps eight probes rolling without waiting for slower peers", async () => {
  const pending = new Map<number, ReturnType<typeof deferred<number>>>();
  const started: number[] = [];
  const released: string[] = [];
  const batch = createSubscriptionDelayBatch(Array.from({ length: 10 }, (_, i) => i), {
    start: async () => "rolling",
    measure: (index) => {
      started.push(index);
      const probe = deferred<number>();
      pending.set(index, probe);
      return probe.promise;
    },
    cancel: async (id) => { released.push(id); },
    isCurrent: () => true,
    onPending: () => undefined,
    onResult: () => undefined,
  });
  await turn();
  assert.equal(started.length, 8);
  pending.get(7)!.resolve(7);
  await turn();
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  for (let index = 0; index < 10; index++) {
    pending.get(index)?.resolve(index);
    await turn();
  }
  await batch.done;
  assert.deepEqual(released, ["rolling"]);
});

test("cancelling delay probes stops scheduling and retains completed results", async () => {
  const pending = new Map<number, ReturnType<typeof deferred<number>>>();
  const results: number[] = [];
  const released: string[] = [];
  const batch = createSubscriptionDelayBatch(Array.from({ length: 12 }, (_, i) => i), {
    start: async () => "cancelled",
    measure: (index) => {
      const probe = deferred<number>();
      pending.set(index, probe);
      return probe.promise;
    },
    cancel: async (id) => { released.push(id); },
    isCurrent: () => true,
    onPending: () => undefined,
    onResult: (_, result) => { results.push(result); },
  });
  await turn();
  pending.get(0)!.resolve(0);
  await turn();
  let cancellationSettled = false;
  const cancellation = batch.cancel().then(() => { cancellationSettled = true; });
  await turn();
  assert.equal(cancellationSettled, false);
  for (let index = 1; index < 12; index++) {
    pending.get(index)?.resolve(index);
    await turn();
  }
  await cancellation;
  await batch.done;
  assert.equal(batch.cancelled, true);
  assert.equal(pending.size, 9);
  assert.deepEqual(results, [0]);
  assert.deepEqual(released, ["cancelled"]);
});

test("cancel during startup waits for its ID, releases it, and starts no probes", async () => {
  const start = deferred<string>();
  const released: string[] = [];
  const probes: number[] = [];
  const batch = createSubscriptionDelayBatch([0, 1], {
    start: () => start.promise,
    measure: async (index) => { probes.push(index); return index; },
    cancel: async (id) => { released.push(id); },
    isCurrent: () => true,
    onPending: () => undefined,
    onResult: () => undefined,
  });
  const cancellation = batch.cancel();
  start.resolve("late-start");
  await cancellation;
  await batch.done;
  assert.deepEqual(probes, []);
  assert.deepEqual(released, ["late-start"]);
});

test("replaced batch cannot publish late results or alter a newer run", async () => {
  const oldProbe = deferred<number>();
  const results: number[] = [];
  const released: string[] = [];
  let current = "old";
  const operations = (id: string) => ({
    start: async () => id,
    measure: () => id === "old" ? oldProbe.promise : Promise.resolve(2),
    cancel: async (runId: string) => { released.push(runId); },
    isCurrent: () => current === id,
    onPending: () => undefined,
    onResult: (_: number, result: number) => { results.push(result); },
  });
  const old = createSubscriptionDelayBatch([0], operations("old"));
  await turn();
  current = "new";
  const next = createSubscriptionDelayBatch([0], operations("new"));
  await next.done;
  oldProbe.resolve(1);
  await old.done;
  assert.deepEqual(results, [2]);
  assert.deepEqual(released, ["new", "old"]);
});

test("failed batch startup does not cancel an unrelated or unknown server run", async () => {
  const released: string[] = [];
  const batch = createSubscriptionDelayBatch([0], {
    start: async () => { throw new Error("start refused"); },
    measure: async () => 0,
    cancel: async (id) => { released.push(id); },
    isCurrent: () => true,
    onPending: () => undefined,
    onResult: () => undefined,
  });
  await assert.rejects(batch.done, /start refused/);
  await batch.cancel();
  assert.deepEqual(released, []);
});

test("common provider prefix is split from endpoint names", () => {
  const { provider, names } = providerPrefix([
    "Geodema - ⚡ Нидерланды",
    "Geodema - 🇩🇪 Германия",
    "Geodema - 🇫🇮 Финляндия",
  ]);
  assert.equal(provider, "Geodema");
  assert.deepEqual(names, ["⚡ Нидерланды", "🇩🇪 Германия", "🇫🇮 Финляндия"]);
});

test("mixed names keep the raw list untouched", () => {
  const input = ["Geodema - NL", "Other - DE"];
  const { provider, names } = providerPrefix(input);
  assert.equal(provider, null);
  assert.deepEqual(names, input);
});

test("prefix must end at a separator boundary, not mid-word", () => {
  const { provider, names } = providerPrefix(["Alpha-NL1", "Alpha-NL2"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Alpha-NL1", "Alpha-NL2"]);
});

test("supports en/em dashes and pipes as separators", () => {
  for (const sep of [" - ", " – ", " — ", " | "]) {
    const { provider, names } = providerPrefix([
      `Prov${sep}A`,
      `Prov${sep}B`,
    ]);
    assert.equal(provider, "Prov", `separator ${sep}`);
    assert.deepEqual(names, ["A", "B"]);
  }
});

test("single endpoint yields no provider", () => {
  const { provider, names } = providerPrefix(["Geodema - NL"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Geodema - NL"]);
});

test("identical names are not treated as a provider prefix", () => {
  const { provider, names } = providerPrefix(["Same", "Same"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Same", "Same"]);
});

test("empty remainder after stripping rejects the split", () => {
  const { provider, names } = providerPrefix(["Prov - ", "Prov - X"]);
  assert.equal(provider, null);
  assert.deepEqual(names, ["Prov - ", "Prov - X"]);
});
