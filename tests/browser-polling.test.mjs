import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { SourceTextModule } from "node:vm";
import ts from "typescript";

const source = await readFile(new URL("../lib/browser-polling.ts", import.meta.url), "utf8").catch(error => {
  if (error.code === "ENOENT") return "export {}";
  throw error;
});
const module = new SourceTextModule(ts.transpileModule(source, { compilerOptions: {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
} }).outputText);
await module.link(() => { throw new Error("Unexpected dependency"); });
await module.evaluate();
const { startPolling } = module.namespace;
const flush = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

test("slow reads and manual refreshes share one request; the next interval starts after completion", async context => {
  assert.equal(typeof startPolling, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const requests = [];
  const poll = startPolling(signal => new Promise(resolve => requests.push({ signal, resolve })), { intervalMs: 5000 });
  await flush();
  context.mock.timers.tick(15000); await flush();
  const manual = poll.refresh();
  assert.equal(requests.length, 1);
  requests[0].resolve(); await manual; await flush();
  context.mock.timers.tick(4999); await flush(); assert.equal(requests.length, 1);
  context.mock.timers.tick(1); await flush(); assert.equal(requests.length, 2);
  poll.stop(); requests[1].resolve(); await flush();
});

test("stop aborts the active request and prevents stale updates and future reads", async context => {
  assert.equal(typeof startPolling, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let resolve, requestSignal, reads = 0, published = 0;
  const poll = startPolling(async signal => {
    reads++; requestSignal = signal;
    await new Promise(done => { resolve = done; });
    if (!signal.aborted) published++;
  }, { intervalMs: 5000 });
  await flush(); poll.stop();
  assert.equal(requestSignal.aborted, true);
  resolve(); await flush();
  context.mock.timers.tick(60000); await flush();
  await poll.refresh();
  assert.equal(reads, 1); assert.equal(published, 0);
});

test("timed out and failed reads release their slot and retry without hiding last good data", async context => {
  assert.equal(typeof startPolling, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let reads = 0, lastGood = "saved result", failures = 0;
  const poll = startPolling(async signal => {
    reads++;
    if (reads === 1) await new Promise((resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
    else lastGood = "updated result";
  }, { intervalMs: 5000, timeoutMs: 2000, onError: () => { failures++; } });
  await flush(); context.mock.timers.tick(2000); await flush();
  assert.equal(reads, 1); assert.equal(failures, 1); assert.equal(lastGood, "saved result");
  context.mock.timers.tick(5000); await flush();
  assert.equal(reads, 2); assert.equal(lastGood, "updated result");
  poll.stop();
});

test("dynamic polling cadence takes effect after a completed read without restarting it", async context => {
  assert.equal(typeof startPolling, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let reads = 0, interval = 60000;
  const poll = startPolling(async () => { reads++; interval = reads === 1 ? 10000 : 60000; }, { intervalMs: () => interval });
  await flush(); context.mock.timers.tick(10000); await flush(); assert.equal(reads, 2);
  context.mock.timers.tick(10000); await flush(); assert.equal(reads, 2);
  context.mock.timers.tick(50000); await flush(); assert.equal(reads, 3);
  poll.stop();
});

test("a manual refresh after a mutation waits for the current read and then reads fresh state once", async context => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const requests = [];
  const poll = startPolling(() => new Promise(resolve => requests.push(resolve)), { intervalMs: 5000 });
  await flush();
  const first = poll.refresh({ afterCurrent: true }), second = poll.refresh({ afterCurrent: true });
  assert.equal(requests.length, 1);
  requests[0](); await flush();
  assert.equal(requests.length, 2);
  requests[1](); await Promise.all([first, second]);
  assert.equal(requests.length, 2);
  poll.stop();
});

test("a failed batch cancels unfinished sibling requests before another polling cycle", async context => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let pendingSignal;
  const poll = startPolling(async signal => {
    pendingSignal = signal;
    // One request in Promise.all may fail while another fetch still awaits a response.
    throw new Error("One endpoint failed");
  }, { intervalMs: 5000 });
  await flush();
  assert.equal(pendingSignal.aborted, true);
  poll.stop();
});
