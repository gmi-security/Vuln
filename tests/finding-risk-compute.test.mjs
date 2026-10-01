// node --experimental-vm-modules --test tests/finding-risk-compute.test.mjs
//
// Exercises computeFindingRiskForTenant (lib/finding-risk-compute.ts) against
// mocked Spotlight records, CVE enrichment, and ticket coverage: a KEV'd
// internet-facing finding scores high and lands Swath 1; verification status
// derives correctly from the existing closed/fix_verified_state fields
// (detected -> ticket_created -> pending_verification -> verified_remediated,
// plus reopened); and one malformed record doesn't abort the whole pass.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

function loader(overrides = {}) {
  const cache = new Map();
  async function load(path) {
    path = resolve(path);
    if (cache.has(path)) return cache.get(path);
    const code = ts.transpileModule(await readFile(path, "utf8"), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
    const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
    await mod.link(async (name) => {
      if (overrides[name]) { const values = overrides[name]; return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); }); }
      if (name.startsWith(".")) return load(resolve(dirname(path), `${name}.ts`));
      if (name.startsWith("@/")) return load(resolve(".", `${name.slice(2)}.ts`));
      const values = await import(name);
      return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
    });
    return mod;
  }
  return async (path) => { const mod = await load(path); await mod.evaluate(); return mod.namespace; };
}

function record(overrides = {}) {
  return {
    sourceId: "s1", tenantKey: "tenant-1", companyId: "CO-1", hostname: "web01.ext.corp.com", localIp: "10.0.0.5", externalIp: "",
    cve: "CVE-2026-1111", severity: "Critical", status: "open", description: "", remediation: "", observedAt: "2026-09-01T00:00:00.000Z",
    raw: { cve: { cvss_v3: 9.8, exploit_status: 80, published_date: "2026-01-01" } },
    ...overrides,
  };
}

async function loadCompute({ records, ticketRows = [], enrichment = new Map() }) {
  const upserted = [];
  const engine = await loader()("lib/risk-scoring.ts");
  const mod = await loader({
    "./spotlight-record-store": { listCompletedSpotlightRecords: async (tenantKey, limit, afterId) => (afterId ?? "") === "" ? records : [] },
    "./risk-scoring-store": {
      riskScoringDatabase: async () => ({ query: async () => ({ rows: [] }) }),
      getRiskConfig: async () => ({ weights: engine.DEFAULT_RISK_WEIGHTS, swathThresholds: engine.DEFAULT_SWATH_THRESHOLDS }),
      getCveEnrichment: async (_db, _cves) => enrichment,
      upsertFindingRiskBatch: async (_db, _tenantKey, inputs) => { upserted.push(...inputs); return { scored: inputs.length }; },
    },
    "./patch-ticket-store": { patchTicketDatabase: async () => ({ query: async () => ({ rows: ticketRows }) }) },
  })("lib/finding-risk-compute.ts");
  return { mod, upserted };
}

test("a KEV'd, internet-facing, high-CVSS finding scores high and lands Swath 1", async () => {
  const { mod, upserted } = await loadCompute({
    records: [record({ hostname: "web-prod01.mycompany.com" })],
    enrichment: new Map([["CVE-2026-1111", { cvssScore: 9.8, epssProbability: 0.9, epssPercentile: 0.98, cisaKev: true, kevRansomware: false, publishedDate: null }]]),
  });
  const result = await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(result.findingsScored, 1);
  assert.equal(result.errors, 0);
  assert.equal(upserted.length, 1);
  assert.equal(upserted[0].cisaKev, true);
  // Reaches Swath 1 via the KEV+internet-facing emergency elevation, not
  // necessarily by crossing 800 on the numeric score alone (this finding's
  // asset criticality is "High", not "Crown Jewel") -- that's the intended
  // override behavior, exercised here rather than assumed.
  assert.equal(upserted[0].effectiveSwath, 1);
  assert.ok(upserted[0].riskScore >= 600, `expected a meaningfully high score, got ${upserted[0].riskScore}`);
});

test("verification status: no covering ticket means 'detected'", async () => {
  const { mod, upserted } = await loadCompute({ records: [record()], ticketRows: [] });
  await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(upserted[0].verificationStatus, "detected");
});

test("verification status: an open covering ticket means 'ticket_created'", async () => {
  const { mod, upserted } = await loadCompute({
    records: [record()],
    ticketRows: [{ cves: ["CVE-2026-1111"], ticket_id: 555, closed: false, fix_verified_state: null }],
  });
  await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(upserted[0].verificationStatus, "ticket_created");
});

test("verification status: a closed ticket with no verification yet means 'pending_verification', not 'verified'", async () => {
  const { mod, upserted } = await loadCompute({
    records: [record()],
    ticketRows: [{ cves: ["CVE-2026-1111"], ticket_id: 555, closed: true, fix_verified_state: null }],
  });
  await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(upserted[0].verificationStatus, "pending_verification");
});

test("verification status: fix_verified_state='verified' means 'verified_remediated'", async () => {
  const { mod, upserted } = await loadCompute({
    records: [record()],
    ticketRows: [{ cves: ["CVE-2026-1111"], ticket_id: 555, closed: true, fix_verified_state: "verified" }],
  });
  await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(upserted[0].verificationStatus, "verified_remediated");
});

test("verification status: fix_verified_state='still_open' on a now-open ticket means 'reopened' -- a rescan found it's back", async () => {
  const { mod, upserted } = await loadCompute({
    records: [record()],
    ticketRows: [{ cves: ["CVE-2026-1111"], ticket_id: 555, closed: false, fix_verified_state: "still_open" }],
  });
  await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(upserted[0].verificationStatus, "reopened");
});

test("one malformed record does not abort the rest of the tenant's pass", async () => {
  const bad = record({ cve: "CVE-2026-1111", raw: null });
  const good = record({ cve: "CVE-2026-2222", sourceId: "s2" });
  const { mod, upserted } = await loadCompute({ records: [bad, good] });
  const result = await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  // Neither record actually throws here since extractCvss/extractKnownExploit
  // null-guard on raw -- this proves the null-raw case is handled, not skipped.
  assert.equal(result.errors, 0);
  assert.equal(upserted.length, 2);
});

test("a failed batch write counts as an error per record but does not abort the tenant's pass", async () => {
  const engine = await loader()("lib/risk-scoring.ts");
  const mod = await loader({
    "./spotlight-record-store": { listCompletedSpotlightRecords: async (_tenantKey, _limit, afterId) => (afterId ?? "") === "" ? [record(), record({ cve: "CVE-2026-2222", sourceId: "s2" })] : [] },
    "./risk-scoring-store": {
      riskScoringDatabase: async () => ({ query: async () => ({ rows: [] }) }),
      getRiskConfig: async () => ({ weights: engine.DEFAULT_RISK_WEIGHTS, swathThresholds: engine.DEFAULT_SWATH_THRESHOLDS }),
      getCveEnrichment: async () => new Map(),
      upsertFindingRiskBatch: async () => { throw new Error("connection reset"); },
    },
    "./patch-ticket-store": { patchTicketDatabase: async () => ({ query: async () => ({ rows: [] }) }) },
  })("lib/finding-risk-compute.ts");
  const result = await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  assert.equal(result.findingsScored, 0);
  assert.equal(result.errors, 2);
});

test("pages by source_id cursor, not OFFSET -- a full page requests the next page starting after the last sourceId seen", async () => {
  const engine = await loader()("lib/risk-scoring.ts");
  const page1 = Array.from({ length: 1000 }, (_, i) => record({ sourceId: `s${String(i + 1).padStart(4, "0")}` }));
  const page2 = [record({ sourceId: "s1001", cve: "CVE-2026-2222" })];
  const calls = [];
  const mod = await loader({
    "./spotlight-record-store": {
      listCompletedSpotlightRecords: async (_tenantKey, _limit, afterId) => {
        calls.push(afterId);
        if ((afterId ?? "") === "") return page1;
        if (afterId === "s1000") return page2;
        return [];
      },
    },
    "./risk-scoring-store": {
      riskScoringDatabase: async () => ({ query: async () => ({ rows: [] }) }),
      getRiskConfig: async () => ({ weights: engine.DEFAULT_RISK_WEIGHTS, swathThresholds: engine.DEFAULT_SWATH_THRESHOLDS }),
      getCveEnrichment: async () => new Map(),
      upsertFindingRiskBatch: async (_db, _tenantKey, inputs) => ({ scored: inputs.length }),
    },
    "./patch-ticket-store": { patchTicketDatabase: async () => ({ query: async () => ({ rows: [] }) }) },
  })("lib/finding-risk-compute.ts");
  const result = await mod.computeFindingRiskForTenant("tenant-1", "CO-1");
  // Three calls: "" -> page1 (1000, so keep going), "s1000" -> page2 (1, so stop).
  assert.deepEqual(calls, ["", "s1000"]);
  assert.equal(result.findingsScored, 1001);
});
