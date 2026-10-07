// node --experimental-vm-modules tests/spotlight-resumable-import.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/spotlight-resumable-import.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(() => { throw new Error("Resumable import core must have no runtime dependencies."); });
await module.evaluate();
const { runResumableSpotlightImport, runPartitionedSpotlightImport } = module.namespace;

const selection = { companyId: "CO-147284", tenantKey: "CO-147284",
  config: { label: "Atlas HealthCare", customerName: "Atlas HealthCare", baseUrl: "https://api.crowdstrike.com" } };
const sourceRecord = id => ({ id, raw: { id, host_info: { hostname: id } },
  hostname: id, localIp: "", externalIp: "", cve: "CVE-2026-1234",
  severity: "High", status: "open", description: "Issue", remediation: "Patch" });

test("a restarted hydration run resumes after its committed source ID", async () => {
  const seen = [];
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "hydrating",
      queryCursor: "", hydrationCursor: "source-1", discoveredCount: 2, expectedCount: 2, hydratedCount: 1 }),
    createSession: async () => ({
      queryPage: async () => { throw new Error("Discovery must not repeat after hydration began."); },
      hydrateIds: async ids => { seen.push(...ids); return ids.map(sourceRecord); },
    }),
    savePage: async () => { throw new Error("Discovery must not repeat."); },
    nextIds: async (_id, _tenant, after) => after === "source-1" ? ["source-2"] : [],
    write: async (_id, _tenant, ids, rows) => {
      assert.deepEqual(ids, ["source-2"]);
      assert.deepEqual(rows.map(row => row.sourceId), ids);
      return 1;
    },
    complete: async () => ({ findingsImported: 2, hostsAffected: 2 }),
    fail: async () => { throw new Error("The resumed run must not fail."); },
    abandon: async () => { throw new Error("Hydration must not abandon discovery."); },
    prune: async () => {},
  };
  const result = await runResumableSpotlightImport(selection, deps, () => {});
  assert.deepEqual(seen, ["source-2"]);
  assert.equal(result.findingsImported, 2);
});

test("a failed discovery page resumes at its committed cursor on the next invocation", async () => {
  let checkpoint = { id: "run-1", tenantKey: "CO-147284", phase: "discovering",
    queryCursor: "", hydrationCursor: "", discoveredCount: 0, expectedCount: null, hydratedCount: 0 };
  const queried = [], failed = [], savedIds = [];
  let shouldFail = true;
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => checkpoint,
    createSession: async () => ({
      queryPage: async cursor => {
        queried.push(cursor);
        if (cursor === "next" && shouldFail) throw new Error("Spotlight query 500: temporary");
        return cursor ? { ids: ["source-2"], next: "", total: 2 }
          : { ids: ["source-1"], next: "next", total: 2 };
      },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePage: async (_id, _tenant, prior, ids, next) => {
      assert.equal(prior, checkpoint.queryCursor);
      savedIds.push(...ids);
      checkpoint = { ...checkpoint, queryCursor: next,
        discoveredCount: checkpoint.discoveredCount + ids.length,
        phase: next ? "discovering" : "hydrating", expectedCount: next ? null : 2 };
      return checkpoint;
    },
    nextIds: async (_id, _tenant, after) => after ? [] : [...savedIds].sort(),
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 2, hostsAffected: 2 }),
    fail: async (_id, error) => { failed.push(error); },
    abandon: async () => { throw new Error("HTTP 500 must not reset discovery."); },
    prune: async () => {},
  };
  await assert.rejects(() => runResumableSpotlightImport(selection, deps, () => {}), /Spotlight query 500/);
  shouldFail = false;
  const result = await runResumableSpotlightImport(selection, deps, () => {});
  assert.equal(result.findingsImported, 2);
  assert.deepEqual(queried, ["", "next", "next"]);
  assert.deepEqual(savedIds, ["source-1", "source-2"]);
  assert.equal(failed.length, 1);
});

test("worker lock is acquired before resume and released after completion", async () => {
  const steps = [];
  const deps = {
    acquire: async () => { steps.push("acquire"); return {
      assertHeld: () => steps.push("held"), release: async () => { steps.push("release"); },
    }; },
    begin: async () => { steps.push("begin"); return { id: "run-1", tenantKey: "CO-147284",
      phase: "hydrating", queryCursor: "", hydrationCursor: "", discoveredCount: 0,
      expectedCount: 0, hydratedCount: 0 }; },
    createSession: async () => ({ queryPage: async () => { throw new Error("No discovery."); },
      hydrateIds: async () => [] }),
    savePage: async () => { throw new Error("No discovery."); },
    nextIds: async () => [], write: async () => 0,
    complete: async () => { steps.push("complete"); return { findingsImported: 0, hostsAffected: 0 }; },
    fail: async () => {}, abandon: async () => {}, prune: async () => {},
  };
  await runResumableSpotlightImport(selection, deps, () => {});
  assert.equal(steps[0], "acquire");
  assert.ok(steps.indexOf("begin") > steps.indexOf("acquire"));
  assert.ok(steps.indexOf("release") > steps.indexOf("complete"));
});

test("an expired saved cursor abandons only discovery and retries from the first page", async () => {
  const old = { id: "old-run", tenantKey: "CO-147284", phase: "discovering",
    queryCursor: "expired", hydrationCursor: "", discoveredCount: 400, expectedCount: null, hydratedCount: 0 };
  const fresh = { ...old, id: "new-run", queryCursor: "", discoveredCount: 0 };
  const queried = [], abandoned = [];
  let starts = 0;
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ++starts === 1 ? old : fresh,
    createSession: async () => ({ queryPage: async cursor => {
      queried.push(cursor);
      if (cursor === "expired") throw new Error("Spotlight query 400: invalid after token");
      return { ids: ["source-1"], next: "", total: 1 };
    }, hydrateIds: async ids => ids.map(sourceRecord) }),
    savePage: async (runId) => ({ ...fresh, id: runId, phase: "hydrating",
      discoveredCount: 1, expectedCount: 1 }),
    nextIds: async (_id, _tenant, after) => after ? [] : ["source-1"],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async runId => { assert.equal(runId, "new-run"); return { findingsImported: 1, hostsAffected: 1 }; },
    fail: async () => {}, abandon: async runId => { abandoned.push(runId); }, prune: async () => {},
  };
  const result = await runResumableSpotlightImport(selection, deps, () => {});
  assert.equal(result.findingsImported, 1);
  assert.deepEqual(queried, ["expired", ""]);
  assert.deepEqual(abandoned, ["old-run"]);
});

test("incomplete hydration fails without promoting the generation", async () => {
  let promoted = false, failed = false;
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "hydrating",
      queryCursor: "", hydrationCursor: "", discoveredCount: 2, expectedCount: 2, hydratedCount: 0 }),
    createSession: async () => ({ queryPage: async () => { throw new Error("No discovery."); },
      hydrateIds: async () => [sourceRecord("source-1")] }),
    savePage: async () => { throw new Error("No discovery."); },
    nextIds: async () => ["source-1", "source-2"],
    write: async () => { throw new Error("Incomplete data must not be stored."); },
    complete: async () => { promoted = true; return { findingsImported: 1, hostsAffected: 1 }; },
    fail: async () => { failed = true; }, abandon: async () => {}, prune: async () => {},
  };
  await assert.rejects(() => runResumableSpotlightImport(selection, deps, () => {}), /hydration IDs mismatch/i);
  assert.equal(failed, true);
  assert.equal(promoted, false);
});

// runPartitionedSpotlightImport: discovery walked as several independent
// cursors (one per partition_key) concurrently instead of one sequential
// walk. Built after a real tenant's 2.1M-finding Spotlight inventory showed
// sequential discovery alone would take hours. Hydration is untouched and
// shared with the single-cursor path above.

test("two discovery partitions query their own filter and feed one shared hydration phase", async () => {
  const state = {
    open: { queryCursor: "", discoveredCount: 0, done: false },
    reopen: { queryCursor: "", discoveredCount: 0, done: false },
  };
  const snapshot = (runId) => {
    const allDone = Object.values(state).every(p => p.done);
    const discoveredCount = Object.values(state).reduce((sum, p) => sum + p.discoveredCount, 0);
    return { id: runId, tenantKey: "CO-147284", phase: allDone ? "hydrating" : "discovering",
      partitions: Object.entries(state).map(([key, value]) => ({ key, ...value })),
      hydrationCursor: "", discoveredCount, expectedCount: allDone ? discoveredCount : null, hydratedCount: 0 };
  };
  const queried = [];
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async (_tenantKey, keys) => ({ id: "run-1", tenantKey: "CO-147284", phase: "discovering",
      partitions: keys.map(key => ({ key, ...state[key] })),
      hydrationCursor: "", discoveredCount: 0, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({
      queryPage: async (after, filter) => {
        queried.push({ after, filter });
        if (filter === "status:'open'") return { ids: ["o1", "o2"], next: "", total: 2 };
        if (filter === "status:'reopen'") return { ids: ["r1"], next: "", total: 1 };
        throw new Error(`unexpected filter: ${filter}`);
      },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePartitionPage: async (runId, _tenantKey, key, _prior, ids, next) => {
      state[key] = { queryCursor: next, discoveredCount: state[key].discoveredCount + ids.length, done: next === "" };
      return snapshot(runId);
    },
    resetPartition: async () => { throw new Error("must not reset -- no error injected"); },
    getRunState: async (runId) => snapshot(runId),
    nextIds: async (_id, _tenant, after) => after === "" ? ["o1", "o2", "r1"] : [],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 3, hostsAffected: 3 }),
    fail: async () => { throw new Error("must not fail"); },
    prune: async () => {},
  };
  const result = await runPartitionedSpotlightImport(selection,
    [{ key: "open", filter: "status:'open'" }, { key: "reopen", filter: "status:'reopen'" }], deps, () => {});
  assert.equal(result.findingsImported, 3);
  assert.deepEqual(queried.map(q => q.filter).sort(), ["status:'open'", "status:'reopen'"]);
});

test("a partition's rejected cursor resets only that partition via resetPartition, not a whole-run abandon", async () => {
  let checkpoint = { key: "open", queryCursor: "expired", discoveredCount: 400, done: false };
  const queried = [], reset = [];
  const snapshot = (runId) => ({ id: runId, tenantKey: "CO-147284", phase: checkpoint.done ? "hydrating" : "discovering",
    partitions: [checkpoint], hydrationCursor: "", discoveredCount: checkpoint.discoveredCount,
    expectedCount: checkpoint.done ? checkpoint.discoveredCount : null, hydratedCount: 0 });
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "discovering",
      partitions: [checkpoint], hydrationCursor: "", discoveredCount: 400, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({
      queryPage: async cursor => {
        queried.push(cursor);
        if (cursor === "expired") throw new Error("Spotlight query 400: invalid after token");
        return { ids: ["source-1"], next: "", total: null };
      },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePartitionPage: async (runId, _tenantKey, key, _prior, ids, next) => {
      checkpoint = { key, queryCursor: next, discoveredCount: checkpoint.discoveredCount + ids.length, done: next === "" };
      return snapshot(runId);
    },
    resetPartition: async (_runId, _tenantKey, key) => { reset.push(key); checkpoint = { ...checkpoint, queryCursor: "" }; },
    getRunState: async (runId) => snapshot(runId),
    nextIds: async (_id, _tenant, after) => after === "" ? ["source-1"] : [],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 1, hostsAffected: 1 }),
    fail: async () => { throw new Error("must not fail -- the self-heal should recover"); },
    prune: async () => {},
  };
  const result = await runPartitionedSpotlightImport(selection, [{ key: "open", filter: "status:'open'" }], deps, () => {});
  assert.equal(result.findingsImported, 1);
  assert.deepEqual(reset, ["open"]);
  assert.deepEqual(queried, ["expired", ""]);
});

test("a partition's cursor can reset more than once in one run (CrowdStrike's search context can expire repeatedly over a multi-hour walk)", async () => {
  let checkpoint = { key: "open", queryCursor: "", discoveredCount: 0, done: false };
  const reset = [];
  // Each cursor CrowdStrike hands back expires before it's used -- twice in
  // a row, matching the live failure (910,186 fetched, expired, reset,
  // expired again). A single allowed reset used to make this throw on the
  // second expiry instead of recovering.
  const expiredCursors = new Set(["expired-1", "expired-2"]);
  const snapshot = (runId) => ({ id: runId, tenantKey: "CO-147284", phase: checkpoint.done ? "hydrating" : "discovering",
    partitions: [checkpoint], hydrationCursor: "", discoveredCount: checkpoint.discoveredCount,
    expectedCount: checkpoint.done ? checkpoint.discoveredCount : null, hydratedCount: 0 });
  let page = 0;
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "discovering",
      partitions: [checkpoint], hydrationCursor: "", discoveredCount: 0, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({
      queryPage: async cursor => {
        if (expiredCursors.has(cursor)) throw new Error("Spotlight query 404: Search context expired, 'after' key no longer valid");
        page += 1;
        if (page === 1) return { ids: ["source-1"], next: "expired-1", total: null };
        if (page === 2) return { ids: ["source-2"], next: "expired-2", total: null };
        return { ids: [`source-${page}`], next: "", total: null };
      },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePartitionPage: async (runId, _tenantKey, key, _prior, ids, next) => {
      checkpoint = { key, queryCursor: next, discoveredCount: checkpoint.discoveredCount + ids.length, done: next === "" };
      return snapshot(runId);
    },
    resetPartition: async (_runId, _tenantKey, key) => { reset.push(key); checkpoint = { ...checkpoint, queryCursor: "" }; },
    getRunState: async (runId) => snapshot(runId),
    nextIds: async (_id, _tenant, after) => after === "" ? ["source-1", "source-2", "source-3"] : [],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 3, hostsAffected: 1 }),
    fail: async () => { throw new Error("must not fail -- both expiries should self-heal via reset"); },
    prune: async () => {},
  };
  const result = await runPartitionedSpotlightImport(selection, [{ key: "open", filter: "status:'open'" }], deps, () => {});
  assert.equal(result.findingsImported, 3);
  assert.deepEqual(reset, ["open", "open"]);
});

test("resuming skips an already-done partition and only continues the one still open", async () => {
  const queried = [];
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "discovering",
      partitions: [{ key: "open", queryCursor: "", discoveredCount: 400, done: true },
        { key: "reopen", queryCursor: "mid", discoveredCount: 100, done: false }],
      hydrationCursor: "", discoveredCount: 500, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({
      queryPage: async (after, filter) => { queried.push({ after, filter }); return { ids: ["r2"], next: "", total: null }; },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePartitionPage: async (runId, _tenantKey, _key, _prior, _ids, next) => ({ id: runId, tenantKey: "CO-147284", phase: "hydrating",
      partitions: [{ key: "open", queryCursor: "", discoveredCount: 400, done: true },
        { key: "reopen", queryCursor: next, discoveredCount: 101, done: true }],
      hydrationCursor: "", discoveredCount: 501, expectedCount: 501, hydratedCount: 0 }),
    resetPartition: async () => { throw new Error("must not reset"); },
    getRunState: async (runId) => ({ id: runId, tenantKey: "CO-147284", phase: "hydrating",
      partitions: [{ key: "open", queryCursor: "", discoveredCount: 400, done: true },
        { key: "reopen", queryCursor: "", discoveredCount: 101, done: true }],
      hydrationCursor: "", discoveredCount: 501, expectedCount: 501, hydratedCount: 0 }),
    nextIds: async (_id, _tenant, after) => after === "" ? ["r2"] : [],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 1, hostsAffected: 1 }),
    fail: async () => { throw new Error("must not fail"); },
    prune: async () => {},
  };
  const result = await runPartitionedSpotlightImport(selection,
    [{ key: "open", filter: "status:'open'" }, { key: "reopen", filter: "status:'reopen'" }], deps, () => {});
  assert.equal(result.findingsImported, 1);
  assert.deepEqual(queried, [{ after: "mid", filter: "status:'reopen'" }]);
});

test("the orchestrator re-fetches the true run state after concurrent discovery instead of trusting a stale in-memory phase", async () => {
  // A real race: whichever partition's savePartitionPage transaction happens
  // to resolve last in JS-assignment order is not guaranteed to be the one
  // Postgres actually committed last, so the in-memory `run` after
  // Promise.all cannot be trusted for the phase transition -- this simulates
  // the worst case (begin() itself already stale) to prove the orchestrator
  // re-reads rather than ever leaning on that value.
  let getRunStateCalls = 0;
  const deps = {
    acquire: async () => ({ assertHeld: () => {}, release: async () => {} }),
    begin: async (_tenantKey, keys) => ({ id: "run-1", tenantKey: "CO-147284",
      phase: "discovering", // stale on purpose: every partition below is already done
      partitions: keys.map(key => ({ key, queryCursor: "", discoveredCount: 1, done: true })),
      hydrationCursor: "", discoveredCount: 2, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({
      queryPage: async () => { throw new Error("must not query -- every partition is already done"); },
      hydrateIds: async ids => ids.map(sourceRecord),
    }),
    savePartitionPage: async () => { throw new Error("must not save -- every partition is already done"); },
    resetPartition: async () => { throw new Error("must not reset"); },
    getRunState: async (runId, tenantKey) => {
      getRunStateCalls++;
      return { id: runId, tenantKey, phase: "hydrating",
        partitions: [{ key: "open", queryCursor: "", discoveredCount: 1, done: true },
          { key: "reopen", queryCursor: "", discoveredCount: 1, done: true }],
        hydrationCursor: "", discoveredCount: 2, expectedCount: 2, hydratedCount: 0 };
    },
    nextIds: async (_id, _tenant, after) => after === "" ? ["source-1", "source-2"] : [],
    write: async (_id, _tenant, ids) => ids.length,
    complete: async () => ({ findingsImported: 2, hostsAffected: 2 }),
    fail: async () => { throw new Error("must not fail"); },
    prune: async () => {},
  };
  const result = await runPartitionedSpotlightImport(selection,
    [{ key: "open", filter: "status:'open'" }, { key: "reopen", filter: "status:'reopen'" }], deps, () => {});
  assert.equal(result.findingsImported, 2);
  assert.equal(getRunStateCalls, 1, "must re-fetch the true state exactly once after the concurrent discovery loops resolve");
});

test("worker lock is acquired before begin and released after completion (partitioned)", async () => {
  const steps = [];
  const deps = {
    acquire: async () => { steps.push("acquire"); return {
      assertHeld: () => steps.push("held"), release: async () => { steps.push("release"); },
    }; },
    begin: async (_tenantKey, keys) => { steps.push("begin"); return { id: "run-1", tenantKey: "CO-147284",
      phase: "hydrating", partitions: keys.map(key => ({ key, queryCursor: "", discoveredCount: 0, done: true })),
      hydrationCursor: "", discoveredCount: 0, expectedCount: 0, hydratedCount: 0 }; },
    createSession: async () => ({ queryPage: async () => { throw new Error("No discovery."); },
      hydrateIds: async () => [] }),
    savePartitionPage: async () => { throw new Error("No discovery."); },
    resetPartition: async () => { throw new Error("No discovery."); },
    getRunState: async () => { throw new Error("must not be called -- run already began in hydrating phase"); },
    nextIds: async () => [], write: async () => 0,
    complete: async () => { steps.push("complete"); return { findingsImported: 0, hostsAffected: 0 }; },
    fail: async () => {}, prune: async () => {},
  };
  await runPartitionedSpotlightImport(selection, [{ key: "open", filter: "status:'open'" }], deps, () => {});
  assert.equal(steps[0], "acquire");
  assert.ok(steps.indexOf("begin") > steps.indexOf("acquire"));
  assert.ok(steps.indexOf("release") > steps.indexOf("complete"));
});

test("a worker that loses its database lock cannot mark another worker's run failed", async () => {
  let checks = 0, failed = false;
  const deps = {
    acquire: async () => ({ assertHeld: () => {
      if (++checks > 1) throw new Error("Spotlight worker lost its database lock");
    }, release: async () => {} }),
    begin: async () => ({ id: "run-1", tenantKey: "CO-147284", phase: "discovering",
      queryCursor: "", hydrationCursor: "", discoveredCount: 0, expectedCount: null, hydratedCount: 0 }),
    createSession: async () => ({ queryPage: async () => ({ ids: ["source-1"], next: "", total: 1 }),
      hydrateIds: async () => [] }),
    savePage: async () => { throw new Error("Lost worker must not write."); },
    nextIds: async () => [], write: async () => 0,
    complete: async () => { throw new Error("Lost worker must not promote."); },
    fail: async () => { failed = true; }, abandon: async () => {}, prune: async () => {},
  };
  await assert.rejects(() => runResumableSpotlightImport(selection, deps, () => {}), /lost its database lock/i);
  assert.equal(failed, false);
});
