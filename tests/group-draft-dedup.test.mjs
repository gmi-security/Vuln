// node --experimental-vm-modules --test tests/group-draft-dedup.test.mjs
//
// Exercises sweepSupersededGroupDrafts's JS-side orchestration in isolation
// (a fake db.query) -- the actual ranking/grouping is a single SQL statement
// (ROW_NUMBER PARTITION BY remediation+tenant+customer, keep the newest
// pending draft, dismiss the rest), which is DB logic this codebase verifies
// against real Postgres rather than a mock (see the gated integration test).
// This covers what the JS layer must get right: every id the UPDATE reports
// as dismissed gets exactly one audit row with actor "auto-dedup", and an
// empty result does nothing further.
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

function fakeDb({ updateRows }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.trim().startsWith("WITH ranked")) return { rows: updateRows, rowCount: updateRows.length };
      return { rows: [], rowCount: 1 }; // INSERT INTO ..._audit
    },
  };
}

async function loadDedup(db) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db },
    "./elastic-vuln-server": { elasticVulnEnabled: () => false },
  })("lib/group-draft-dedup.ts");
}

test("every dismissed id gets exactly one audit row with actor auto-dedup", async () => {
  const db = fakeDb({ updateRows: [{ id: "a" }, { id: "b" }] });
  const dedup = await loadDedup(db);
  const result = await dedup.sweepSupersededGroupDrafts();
  assert.deepEqual(result, { dismissed: 2 });
  const audits = db.calls.filter((c) => c.sql.includes("patch_group_ticket_audit"));
  assert.equal(audits.length, 2);
  assert.deepEqual(audits.map((c) => c.params), [["a", "auto-dedup"], ["b", "auto-dedup"]]);
  for (const audit of audits) assert.match(audit.sql, /'group\.dismissed\.superseded'/);
});

test("the update sweeps only still-pending prepared drafts, never approved ones", async () => {
  const db = fakeDb({ updateRows: [] });
  const dedup = await loadDedup(db);
  const update = db.calls; // populated by the call below
  await dedup.sweepSupersededGroupDrafts();
  const sweep = update.find((c) => c.sql.trim().startsWith("WITH ranked"));
  assert.match(sweep.sql, /state='prepared' AND review_state='pending'/);
  assert.doesNotMatch(sweep.sql, /review_state='approved'/);
});

test("no superseded drafts means no audit rows and dismissed: 0", async () => {
  const db = fakeDb({ updateRows: [] });
  const dedup = await loadDedup(db);
  const result = await dedup.sweepSupersededGroupDrafts();
  assert.deepEqual(result, { dismissed: 0 });
  assert.equal(db.calls.filter((c) => c.sql.includes("_audit")).length, 0);
});
