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
const { runResumableSpotlightImport } = module.namespace;

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
