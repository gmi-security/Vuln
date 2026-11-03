// node --experimental-vm-modules --test tests/greenbone-capacity.test.mjs
import assert from "node:assert/strict";
import test, { after } from "node:test";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";

const source = await readFile("lib/greenbone-capacity.ts", "utf8");
const js = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText;
const module = new SourceTextModule(js);
await module.link(async name => {
  assert.equal(name, "./vulners");
  return new SyntheticModule(["vulnersBridgeConfig"], function () {
    this.setExport("vulnersBridgeConfig", () => null);
  });
});
await module.evaluate();
const { validateGreenboneCapacitySnapshot, readVerifiedGreenboneCapacity } = module.namespace;
const now = Date.parse("2026-11-03T21:00:00.000Z");
const cfg = { baseUrl: "https://scanner.example.invalid", apiKey: "unit-test-key" };
const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
function snapshot(overrides = {}) {
  return {
    source: "gvmd", inventoryComplete: true, scannerHealthy: true,
    generatedAt: new Date(now - 1000).toISOString(),
    totalTasks: 7203,
    statusCounts: {
      New: 12, Requested: 0, Queued: 0, Running: 0,
      "Stop Requested": 0, Done: 6102, Stopped: 752, Interrupted: 337,
    },
    ...overrides,
  };
}
test("valid exhaustive GVM snapshot yields zero scanner workload", () => {
  const result = validateGreenboneCapacitySnapshot(snapshot(), now);
  assert.deepEqual(result, {
    checkedAt: new Date(now - 1000).toISOString(), healthy: true,
    activeTaskCount: 0, queuedTaskCount: 0, requestedTaskCount: 0,
  });
});
test("running, requested, queued and stopping work all count as capacity", () => {
  const p = snapshot();
  p.statusCounts = { ...p.statusCounts, Running: 1, Requested: 1, Queued: 1, "Stop Requested": 1, Done: 6098 };
  assert.deepEqual(
    Object.fromEntries(Object.entries(validateGreenboneCapacitySnapshot(p,now))
      .filter(([k]) => k.endsWith("Count"))),
    { activeTaskCount: 2, queuedTaskCount: 1, requestedTaskCount: 1 },
  );
});
test("last-task-only legacy API response and empty lists never prove an idle scanner", () => {
  for (const p of [{ scans: [{id:"last-task",status:"Done"}] }, [], {scans:[]}]) {
    assert.throws(() => validateGreenboneCapacitySnapshot(p, now), /malformed|unverified/);
  }
});
test("partial, unknown, or inconsistent status counts fail closed", () => {
  const p = snapshot();
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({statusCounts:{New:0}}),now), /partial/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({statusCounts:{...p.statusCounts, Unknown:1}}),now), /partial/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({totalTasks:99}),now), /does not match/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({statusCounts:{...p.statusCounts, Done:-1}}),now), /partial/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({statusCounts:{...p.statusCounts, Running:"0"}}),now), /partial/);
});
test("stale or future timestamp blocks permission", () => {
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({generatedAt:new Date(now-30001).toISOString()}),now), /stale/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({generatedAt:new Date(now+1).toISOString()}),now), /future/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({generatedAt:"bad"}),now), /timestamp/);
});
test("unhealthy scanner, missing complete inventory and forged source rejected", () => {
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({scannerHealthy:false}),now), /unverified/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({inventoryComplete:false}),now), /unverified/);
  assert.throws(() => validateGreenboneCapacitySnapshot(snapshot({source:"bridge-api"}),now), /unverified/);
});
test("read performs exactly one authenticated GET to a dedicated capacity endpoint", async () => {
  let calls = 0;
  globalThis.fetch = async (url,opts) => {
    calls++;
    assert.equal(url, "https://scanner.example.invalid/api/v1/scans/capacity");
    assert.equal(opts.method,"GET");
    assert.equal(opts.headers["X-API-Key"],cfg.apiKey);
    assert.equal(opts.redirect,"error");
    return new Response(JSON.stringify(snapshot({
      generatedAt: new Date().toISOString(),
    })),{status:200});
  };
  const result = await readVerifiedGreenboneCapacity(cfg);
  assert.equal(result.healthy,true);
  assert.equal(calls,1);
});
test("missing scanner-side endpoint and invalid JSON cannot authorize work", async () => {
  globalThis.fetch = async () => new Response("Not found",{status:404});
  await assert.rejects(() => readVerifiedGreenboneCapacity(cfg),/unavailable/);
  globalThis.fetch = async () => new Response(JSON.stringify({scans:[{status:"Done"}]}),{status:200});
  await assert.rejects(() => readVerifiedGreenboneCapacity(cfg),/unverified/);
  await assert.rejects(() => readVerifiedGreenboneCapacity(null),/credentials/);
});
