// node --experimental-vm-modules --test tests/group-severity-backfill.test.mjs
//
// Exercises backfillWorstSeverity in isolation (a fake db.query) -- computing
// worst-of-a-set-of-severities is real code from lib/vuln-sla.ts here, not a
// mock, since it has no runtime dependencies of its own. Covers: a row
// missing worst_severity gets it computed from its own stored packet and
// written back; a row whose packet genuinely carries no severity data is
// left alone (still NULL, same as a freshly-prepared row with no severity
// data would be); and no candidate rows means no writes.
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

function fakeDb({ rows }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.trim().startsWith("SELECT")) return { rows };
      return { rows: [], rowCount: 1 }; // UPDATE
    },
  };
}

async function loadBackfill(db) {
  return loader({ "./patch-ticket-store": { patchTicketDatabase: async () => db } })("lib/group-severity-backfill.ts");
}

test("computes worst_severity from the packet's reviewRows and writes it back", async () => {
  const db = fakeDb({
    rows: [
      { id: "a", packet: { reviewRows: [{ severity: "HIGH" }, { severity: "CRITICAL" }] } },
      { id: "b", packet: { reviewRows: [{ severity: "Low" }, { severity: "Medium" }] } },
    ],
  });
  const backfill = await loadBackfill(db);
  const result = await backfill.backfillWorstSeverity();
  assert.deepEqual(result, { updated: 2 });
  const updates = db.calls.filter((c) => c.sql.trim().startsWith("UPDATE"));
  assert.deepEqual(updates.map((c) => c.params), [["a", "Critical"], ["b", "Medium"]]);
});

test("a row whose packet has no severity data is left alone", async () => {
  const db = fakeDb({ rows: [{ id: "a", packet: { reviewRows: [{ severity: "NONE" }, { severity: "UNKNOWN" }] } }] });
  const backfill = await loadBackfill(db);
  const result = await backfill.backfillWorstSeverity();
  assert.deepEqual(result, { updated: 0 });
  assert.equal(db.calls.filter((c) => c.sql.trim().startsWith("UPDATE")).length, 0);
});

test("no rows missing worst_severity means no writes", async () => {
  const db = fakeDb({ rows: [] });
  const backfill = await loadBackfill(db);
  const result = await backfill.backfillWorstSeverity();
  assert.deepEqual(result, { updated: 0 });
  assert.equal(db.calls.length, 1); // only the initial SELECT
});
