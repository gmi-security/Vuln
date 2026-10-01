// node --experimental-vm-modules --test tests/risk-refresh-scheduler.test.mjs
//
// Exercises refreshAllTenantsRisk (lib/risk-refresh-scheduler.ts) against a
// fake db.query: the tenant-listing query (which joins spotlight_import_
// records and spotlight_import_current, both carrying a tenant_key column)
// must return real tenant_key/company_id values, not throw "column
// reference is ambiguous" -- the exact bug a live production run hit
// because this file had no test coverage of its own before this.
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

// A minimal but real-ish parser: rejects an unqualified column reference
// that exists on more than one joined table, the same way Postgres does --
// this is what actually catches the ambiguity bug, not just a canned
// fixture response.
function fakeRiskDb(tenantRows) {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes("FROM spotlight_import_records r JOIN spotlight_import_current c")) {
      const selectList = sql.slice(sql.indexOf("SELECT") + 6, sql.indexOf(" FROM")).replace("DISTINCT", "").trim();
      for (const col of selectList.split(",").map((c) => c.trim())) {
        if (col === "tenant_key") throw new Error('column reference "tenant_key" is ambiguous');
      }
      return { rows: tenantRows };
    }
    return { rows: [] };
  };
  return { calls, query };
}

async function loadScheduler({ tenantRows, refreshTenantResult = { findingsScored: 0, distinctCves: 0, errors: 0 } }) {
  const riskDb = fakeRiskDb(tenantRows);
  const computeCalls = [];
  const mod = await loader({
    "./elastic-vuln-server": { elasticVulnEnabled: () => true },
    "./cve-enrichment-refresh": { refreshCveEnrichment: async () => ({ kevEntries: 0, epssUpdated: 0, activeExploitationSignals: 0, errors: 0, skipped: 0 }) },
    "./finding-risk-compute": { computeFindingRiskForTenant: async (tenantKey, companyId) => { computeCalls.push({ tenantKey, companyId }); return refreshTenantResult; } },
    "./risk-scoring-store": { riskScoringDatabase: async () => riskDb, recordRiskSnapshot: async () => {} },
    "./swath-ticket-priority": { reconcileTicketPriorityToSwath: async () => ({ checked: 0, updated: 0, errors: 0 }) },
    "./background-job-runs": { recordJobRun: async () => {} },
  })("lib/risk-refresh-scheduler.ts");
  return { mod, riskDb, computeCalls };
}

test("refreshAllTenantsRisk resolves real tenant_key/company_id from the join, not an ambiguous column error", async () => {
  const { mod, computeCalls } = await loadScheduler({ tenantRows: [{ tenant_key: "CO-147284", company_id: "CO-147284" }] });
  const result = await mod.refreshAllTenantsRisk();
  assert.deepEqual(result, { tenantsProcessed: 1, findingsScored: 0, errors: 0 });
  assert.deepEqual(computeCalls, [{ tenantKey: "CO-147284", companyId: "CO-147284" }]);
});

test("no tenants with a current Spotlight generation means no work and no snapshot", async () => {
  const { mod, computeCalls } = await loadScheduler({ tenantRows: [] });
  const result = await mod.refreshAllTenantsRisk();
  assert.deepEqual(result, { tenantsProcessed: 0, findingsScored: 0, errors: 0 });
  assert.equal(computeCalls.length, 0);
});

test("one tenant's failure does not block the others", async () => {
  const riskDb = fakeRiskDb([{ tenant_key: "CO-1", company_id: "CO-1" }, { tenant_key: "CO-2", company_id: "CO-2" }]);
  let call = 0;
  const mod = await loader({
    "./elastic-vuln-server": { elasticVulnEnabled: () => true },
    "./cve-enrichment-refresh": { refreshCveEnrichment: async () => ({ kevEntries: 0, epssUpdated: 0, activeExploitationSignals: 0, errors: 0, skipped: 0 }) },
    "./finding-risk-compute": { computeFindingRiskForTenant: async () => { call++; if (call === 1) throw new Error("CrowdStrike timeout"); return { findingsScored: 5, distinctCves: 5, errors: 0 }; } },
    "./risk-scoring-store": { riskScoringDatabase: async () => riskDb, recordRiskSnapshot: async () => {} },
    "./swath-ticket-priority": { reconcileTicketPriorityToSwath: async () => ({ checked: 0, updated: 0, errors: 0 }) },
    "./background-job-runs": { recordJobRun: async () => {} },
  })("lib/risk-refresh-scheduler.ts");
  const result = await mod.refreshAllTenantsRisk();
  assert.deepEqual(result, { tenantsProcessed: 2, findingsScored: 5, errors: 1 });
});
