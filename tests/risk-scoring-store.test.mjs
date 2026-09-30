// node --experimental-vm-modules --test tests/risk-scoring-store.test.mjs
//
// Exercises lib/risk-scoring-store.ts against a fake db.query (same
// SQL-sniffing fakeDb idiom as the rest of tests/): a fresh finding_risk row
// records risk_history on recalculation, a human Swath override survives a
// later recalculation instead of being silently clobbered, and
// overrideSwath/verification-status writes land the right audit rows.
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

function fakeDb({ existingFindingRow = undefined } = {}) {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes("SELECT id, risk_score, effective_swath, swath_override_by, verification_status FROM finding_risk")) {
      return { rows: existingFindingRow ? [existingFindingRow] : [] };
    }
    if (sql.includes("SELECT effective_swath FROM finding_risk WHERE id=$1")) {
      return { rows: existingFindingRow ? [{ effective_swath: existingFindingRow.effective_swath }] : [] };
    }
    return { rows: [], rowCount: 1 };
  };
  return { calls, query, connect: async () => ({ query, release: () => {} }) };
}

async function loadStore(db) {
  return loader({
    "./persist": { applicationDatabase: () => db },
  })("lib/risk-scoring-store.ts");
}

const INPUT = {
  tenantKey: "tenant-1", companyId: "CO-1", cve: "CVE-2026-1111", hostKey: "host-a", hostname: "host-a.local", severity: "Critical",
  riskScore: 850, technicalScore: 240, exploitLikelihoodScore: 220, threatActivityScore: 200, assetContextScore: 150, additionalContextScore: 40,
  reasons: ["CISA Known Exploited Vulnerability", "Internet-facing asset"],
  calculatedSwath: 1, effectiveSwath: 1, epssProbability: 0.9, epssPercentile: 0.98, cisaKev: true, knownExploit: true,
  activeExploitation: false, ransomwareAssociation: false, internetExposed: true, assetCriticality: "High",
};

test("a brand new finding is inserted with no history row (nothing changed from)", async () => {
  const db = fakeDb({ existingFindingRow: undefined });
  const store = await loadStore(db);
  const result = await store.upsertFindingRisk(db, INPUT);
  assert.ok(result.id);
  assert.equal(result.scoreChanged, true);
  const insert = db.calls.find((c) => c.sql.includes("INSERT INTO finding_risk"));
  assert.ok(insert);
  const history = db.calls.filter((c) => c.sql.includes("INSERT INTO risk_history"));
  assert.equal(history.length, 0);
});

test("recalculating an existing finding with a changed score records risk_history for risk_score", async () => {
  const db = fakeDb({ existingFindingRow: { id: "f1", risk_score: 600, effective_swath: 2, swath_override_by: null, verification_status: "detected" } });
  const store = await loadStore(db);
  const result = await store.upsertFindingRisk(db, INPUT); // new score 850, new effectiveSwath 1
  assert.equal(result.id, "f1");
  const scoreHistory = db.calls.find((c) => c.sql.includes("INSERT INTO risk_history") && c.params[2] === "risk_score");
  assert.ok(scoreHistory);
  assert.deepEqual([scoreHistory.params[3], scoreHistory.params[4]], ["600", "850"]);
  const swathHistory = db.calls.find((c) => c.sql.includes("INSERT INTO risk_history") && c.params[2] === "effective_swath");
  assert.ok(swathHistory);
  assert.deepEqual([swathHistory.params[3], swathHistory.params[4]], ["2", "1"]);
});

test("a human Swath override is preserved across recalculation -- the UPDATE's CASE keeps the override, not the freshly-calculated value", async () => {
  const db = fakeDb({ existingFindingRow: { id: "f1", risk_score: 600, effective_swath: 4, swath_override_by: "chuck", verification_status: "detected" } });
  const store = await loadStore(db);
  await store.upsertFindingRisk(db, { ...INPUT, effectiveSwath: 1 }); // engine says 1, human previously said 4
  const update = db.calls.find((c) => c.sql.includes("ON CONFLICT (tenant_key, cve, host_key) DO UPDATE"));
  assert.ok(update.sql.includes("CASE WHEN finding_risk.swath_override_by IS NULL THEN $16 ELSE finding_risk.effective_swath END"));
  // Because the override is preserved, no effective_swath history entry should be written for this recalculation.
  const swathHistory = db.calls.find((c) => c.sql.includes("INSERT INTO risk_history") && c.params[2] === "effective_swath");
  assert.equal(swathHistory, undefined);
});

test("overrideSwath writes the override columns and a risk_history row with the reason and actor", async () => {
  const db = fakeDb({ existingFindingRow: { id: "f1", effective_swath: 3 } });
  const store = await loadStore(db);
  await store.overrideSwath(db, "f1", 1, "chuck", "Client escalated verbally, treat as emergency");
  const update = db.calls.find((c) => c.sql.includes("UPDATE finding_risk SET effective_swath=$2, swath_override_by=$3"));
  assert.deepEqual(update.params, ["f1", 1, "chuck", "Client escalated verbally, treat as emergency"]);
  const history = db.calls.find((c) => c.sql.includes("INSERT INTO risk_history"));
  assert.deepEqual(history.params, [history.params[0], "f1", "effective_swath", "3", "1", "Client escalated verbally, treat as emergency", "chuck"]);
});

test("overrideSwath on an unknown finding throws instead of silently no-op'ing", async () => {
  const db = fakeDb({ existingFindingRow: undefined });
  const store = await loadStore(db);
  await assert.rejects(() => store.overrideSwath(db, "missing", 1, "chuck", "reason"), /not found/i);
});

test("setVerificationStatus records the transition and sets verified_at only for verified_remediated", async () => {
  const db = fakeDb();
  const store = await loadStore(db);
  await store.setVerificationStatus(db, "f1", "pending_verification", "system");
  const pending = db.calls.find((c) => c.sql.includes("UPDATE finding_risk SET verification_status"));
  assert.match(pending.sql, /verified_at=NULL/);
  db.calls.length = 0;
  await store.setVerificationStatus(db, "f1", "verified_remediated", "system");
  const verified = db.calls.find((c) => c.sql.includes("UPDATE finding_risk SET verification_status"));
  assert.match(verified.sql, /verified_at=now\(\)/);
});

// riskScoringDatabase() itself -- unlike every test above, which passes a
// fake db directly to each function, these actually exercise the connection
// resolution. This is deliberately applicationDatabase(), NOT
// dashboardDatabase(): a live production run found 0 tenants because
// finding_risk had been created via dashboardDatabase() (which can point at
// a separate ELASTIC_VULN_DATABASE_URL pool), while spotlight_import_records
// is only ever written through applicationDatabase() -- so the join between
// them silently matched nothing. These tests are the regression guard for
// that specific mistake being reintroduced.
test("riskScoringDatabase uses applicationDatabase(), not dashboardDatabase() -- the fix for the 0-tenants production bug", async () => {
  const db = fakeDb();
  let dashboardDatabaseCalled = false;
  const store = await loader({
    "./persist": { applicationDatabase: () => db },
    "./elastic-dashboard-store": { dashboardDatabase: async () => { dashboardDatabaseCalled = true; return db; } },
  })("lib/risk-scoring-store.ts");
  const resolved = await store.riskScoringDatabase();
  assert.equal(resolved, db);
  assert.equal(dashboardDatabaseCalled, false, "riskScoringDatabase must not fall back to dashboardDatabase()");
});

test("riskScoringDatabase throws a clear error instead of silently returning undefined when no database is configured", async () => {
  const store = await loader({ "./persist": { applicationDatabase: () => null } })("lib/risk-scoring-store.ts");
  await assert.rejects(() => store.riskScoringDatabase(), /not configured/i);
});
