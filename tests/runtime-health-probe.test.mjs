import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as runtime from "../scripts/runtime-server.mjs";

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const token = "private-health-test-token";
async function serve(context, handler) {
  let socketPath;
  if (process.platform === "win32") socketPath = `\\\\.\\pipe\\vuln-health-${randomUUID()}`;
  else {
    const directory = await mkdtemp(join(tmpdir(), "vuln-health-"));
    socketPath = join(directory, "worker.sock");
    context.after(() => rm(directory, { recursive: true, force: true }));
  }
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
  context.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return socketPath;
}
const flush = async () => { await new Promise(resolve => setImmediate(resolve)); };

test("health probe runs immediately then waits after completion without overlapping slow requests", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.startWorkerHealthProbe, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const first = deferred(), second = deferred(), checked = deferred(); let requests = 0;
  const socketPath = await serve(context, (req, res) => {
    requests++;
    assert.equal(req.url, "/api/health"); assert.equal(req.headers.cookie, undefined);
    assert.equal(req.headers.authorization, undefined); assert.equal(req.headers["x-vuln-runtime-token"], token);
    if (requests === 1) first.resolve(res); else second.resolve(res);
  });
  const stop = runtime.startWorkerHealthProbe({ socketPath, token, intervalMs: 10, timeoutMs: 1000,
    onStatus(status) { if (status.available) checked.resolve(status); } });
  context.after(stop);
  const response = await first.promise;
  context.mock.timers.tick(500); await flush(); assert.equal(requests, 1);
  response.end(JSON.stringify({ ready: true, persistence: { blocked: false }, secret: token, companies: ["confidential"] }));
  const status = await checked.promise;
  assert.deepEqual(Object.keys(status).sort(), ["available", "blocked", "checkedAt", "ready"]);
  assert.equal(status.ready, true); assert.equal(status.blocked, false); assert.equal(typeof status.checkedAt, "string");
  assert.equal(JSON.stringify(status).includes(token), false);
  context.mock.timers.tick(9); await flush(); assert.equal(requests, 1);
  context.mock.timers.tick(1); const next = await second.promise; assert.equal(requests, 2);
  stop(); next.destroy(); context.mock.timers.tick(10000); await flush(); assert.equal(requests, 2);
});

test("a timed-out health read retains the last blocked signal and recovers on a later completed probe", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.startWorkerHealthProbe, "function");
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const blocked = deferred(), hung = deferred(), failed = deferred(), recovered = deferred(); let requests = 0;
  const socketPath = await serve(context, (_req, res) => {
    requests++;
    if (requests === 1) { res.statusCode = 503; res.end(JSON.stringify({ ready: false, persistence: { blocked: true } })); }
    else if (requests === 2) hung.resolve(res);
    else res.end(JSON.stringify({ ready: true, persistence: { blocked: false } }));
  });
  const stop = runtime.startWorkerHealthProbe({ socketPath, token, intervalMs: 10, timeoutMs: 100,
    onStatus(status) {
      if (status.available && status.blocked) blocked.resolve(status);
      if (!status.available && status.blocked) failed.resolve(status);
      if (status.available && status.ready) recovered.resolve(status);
    } });
  context.after(stop);
  await blocked.promise; context.mock.timers.tick(10); await hung.promise;
  context.mock.timers.tick(100); const failure = await failed.promise;
  assert.equal(failure.ready, false); assert.equal(failure.blocked, true);
  context.mock.timers.tick(10); const recovery = await recovered.promise;
  assert.equal(recovery.blocked, false); assert.equal(recovery.ready, true);
});

test("stop aborts an active probe and prevents late health publication", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.startWorkerHealthProbe, "function");
  const started = deferred(), closed = deferred(), states = [];
  const socketPath = await serve(context, (_req, res) => { res.on("close", () => closed.resolve()); started.resolve(); });
  const stop = runtime.startWorkerHealthProbe({ socketPath, token, onStatus: state => states.push(state) });
  context.after(stop);
  await started.promise; const beforeStop = states.length; stop(); await closed.promise; await flush();
  assert.equal(states.length, beforeStop);
});

test("invalid or oversized health responses never become a ready result", { timeout: 5000 }, async context => {
  assert.equal(typeof runtime.startWorkerHealthProbe, "function");
  for (const body of ["not json", JSON.stringify({ ready: "true", persistence: { blocked: false } }), "x".repeat(17000)]) {
    const checked = deferred();
    const socketPath = await serve(context, (_req, res) => res.end(body));
    let calls = 0;
    const stop = runtime.startWorkerHealthProbe({ socketPath, token, onStatus(status) { calls++; if (calls > 1) checked.resolve(status); } });
    context.after(stop);
    const status = await checked.promise; stop();
    assert.equal(status.available, false); assert.equal(status.ready, false); assert.equal(status.blocked, false);
  }
});
