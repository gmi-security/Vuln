// node --experimental-vm-modules tests/spotlight-import.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/spotlight-import.ts", import.meta.url), "utf8");
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(() => { throw new Error("Spotlight import core must have no runtime dependencies."); });
await module.evaluate();
const { selectSpotlightTenant, runSpotlightImport } = module.namespace;

const primary = { label: "primary", clientId: "primary-id", clientSecret: "secret", baseUrl: "https://primary" };
const atlas = { label: "Atlas HealthCare", customerName: "Atlas HealthCare", clientId: "atlas-id", clientSecret: "secret", baseUrl: "https://atlas" };
const companies = [{ id: "CO-147284", name: "Atlas Healthcare" }, { id: "CO-GMI", name: "GMI Scans" }];
const finding = id => ({ id, raw: { id, host_info: { hostname: "atlas-host" } },
  cve: "CVE-2026-1234", hostname: "atlas-host", localIp: "10.0.0.1", externalIp: "",
  severity: "High", status: "open", description: "Issue", remediation: "Apply patch" });

test("empty-body sync selects the Atlas customer binding and never the unnamed primary tenant", () => {
  const selection = selectSpotlightTenant([primary, atlas], companies);
  assert.equal(selection.config.clientId, "atlas-id");
  assert.equal(selection.companyId, "CO-147284");
  assert.equal(selection.tenantKey, "CO-147284");
  assert.equal(selectSpotlightTenant([atlas, primary], companies).config.clientId, "atlas-id");
});

test("multiple named tenants require an explicit company ID", () => {
  const other = { ...atlas, label: "OpenWorks", customerName: "OpenWorks", clientId: "other-id" };
  const roster = [...companies, { id: "CO-OPEN", name: "OpenWorks" }];
  assert.throws(() => selectSpotlightTenant([primary, atlas, other], roster), /company.*id/i);
  assert.equal(selectSpotlightTenant([primary, atlas, other], roster, "CO-147284").config.clientId, "atlas-id");
});

test("refuses to sync when a near-duplicate company sits next to the exact match (the Atlas Healthcare Partners vs Atlas HealthCare bug)", () => {
  const roster = [...companies, { id: "CO-235337", name: "Atlas Healthcare Partners" }];
  assert.throws(
    () => selectSpotlightTenant([primary, atlas], roster),
    /near-empty|looks like the same company|duplicate/i,
  );
  // Resolved (the duplicate is gone) -- the exact match proceeds normally again.
  assert.equal(selectSpotlightTenant([primary, atlas], companies).companyId, "CO-147284");
});

test("Atlas import writes every source ID in bounded batches and reports progress", async () => {
  const selection = selectSpotlightTenant([primary, atlas], companies);
  const written = [], phases = [];
  const result = await runSpotlightImport(selection, {
    batches: async function* (config) {
      assert.equal(config.clientId, "atlas-id");
      yield [finding("source-1")];
      yield [finding("source-2")];
    },
    begin: async () => "run-1",
    write: async (_runId, _tenantKey, rows) => { written.push(...rows); return rows.length; },
    complete: async () => 2,
    fail: async () => { throw new Error("Successful run must not fail."); },
    prune: async () => {},
  }, progress => phases.push(progress));
  assert.equal(result.findingsImported, 2);
  assert.equal(result.hostsAffected, 1);
  assert.deepEqual(written.map(row => row.sourceId), ["source-1", "source-2"]);
  assert.deepEqual(written.map(row => row.raw.id), ["source-1", "source-2"]);
  assert.ok(phases.some(progress => progress.fetched === 1 && progress.stored === 1));
  assert.ok(phases.some(progress => progress.fetched === 2 && progress.stored === 2));
});

test("a failed Atlas page marks its run failed without promotion", async () => {
  const selection = selectSpotlightTenant([primary, atlas], companies);
  let promoted = false, failed = false;
  await assert.rejects(() => runSpotlightImport(selection, {
    batches: async function* () { yield [finding("source-1")]; throw new Error("CrowdStrike page failed"); },
    begin: async () => "run-1",
    write: async () => 1,
    complete: async () => { promoted = true; return 1; },
    fail: async () => { failed = true; },
    prune: async () => {},
  }, () => {}), /CrowdStrike page failed/);
  assert.equal(promoted, false);
  assert.equal(failed, true);
});

test("retry begins a new run before cleanup so cleanup can exclude that running generation", async () => {
  const selection = selectSpotlightTenant([primary, atlas], companies);
  const steps = [];
  await runSpotlightImport(selection, {
    batches: async function* () { yield [finding("source-1")]; },
    prune: async () => { steps.push("prune"); },
    begin: async () => { steps.push("begin"); return "run-2"; },
    write: async () => 1,
    complete: async () => 1,
    fail: async () => {},
  }, () => {});
  assert.deepEqual(steps.slice(0, 2), ["begin", "prune"]);
});

test("Atlas import crosses 80,000 records without retaining batches or collapsing shared host and CVE", async () => {
  const selection = selectSpotlightTenant([primary, atlas], companies);
  const total = 80_400;
  let written = 0, largestBatch = 0, batches = 0, timerRan = false;
  setImmediate(() => { timerRan = true; });
  const result = await runSpotlightImport(selection, {
    batches: async function* (config) {
      assert.equal(config.clientId, "atlas-id");
      for (let start = 0; start < total; start += 400)
        yield Array.from({ length: 400 }, (_, index) => finding(`source-${start + index}`));
    },
    begin: async () => "run-scale",
    write: async (_runId, tenantKey, rows) => {
      assert.equal(tenantKey, "CO-147284");
      assert.equal(rows[0].sourceId, `source-${written}`);
      written += rows.length;
      largestBatch = Math.max(largestBatch, rows.length);
      batches++;
      return rows.length;
    },
    complete: async () => written,
    fail: async () => { throw new Error("Scale fixture must not fail."); },
    prune: async () => {},
  }, () => {});
  assert.equal(result.findingsImported, total);
  assert.equal(result.hostsAffected, 1);
  assert.equal(written, total);
  assert.equal(batches, total / 400);
  assert.equal(largestBatch, 400);
  assert.equal(timerRan, true, "event loop must service other requests during the import");
});
