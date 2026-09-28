// node --experimental-vm-modules --test tests/group-priority-backfill.test.mjs
//
// Exercises backfillTicketPriority in isolation (a fake db.query, mocked
// setGroupTicketPriority/cwPrioritiesBySort/savedConnection): a Critical
// ticket that's never had its priority touched gets the top ConnectWise
// priority; a High one gets the next slot down; a ticket that already has a
// 'ticket.priority.changed' audit entry is left alone (the query itself
// excludes it, so this is really testing the SQL, not JS logic); one
// ticket's ConnectWise call failing does not block the rest; and no
// candidates, no ConnectWise connection, or no priorities available all
// mean no priority-setting calls.
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

async function runWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() { for (let i = next++; i < items.length; i = next++) results[i] = await fn(items[i]); }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function fakeDb({ rows }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      return { rows };
    },
  };
}

async function loadBackfill({ db, savedConnection, setGroupTicketPriority, cwPrioritiesBySort }) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db, savedConnection: savedConnection ?? (async () => ({ revision: 7, value: {} })) },
    "./patch-group-ticket-store": {
      setGroupTicketPriority: setGroupTicketPriority ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./ticket-status-sync": { runWithConcurrency },
    "./connectwise-client": { cwPrioritiesBySort: cwPrioritiesBySort ?? (async () => []) },
  })("lib/group-priority-backfill.ts");
}

test("a Critical ticket never touched gets the top ConnectWise priority", async () => {
  const db = fakeDb({ rows: [{ id: "a", worst_severity: "Critical" }] });
  const calls = [];
  const backfill = await loadBackfill({
    db,
    setGroupTicketPriority: async (id, priorityId, actor) => { calls.push({ id, priorityId, actor }); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }],
  });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 1, updated: 1, errors: 0 });
  assert.deepEqual(calls, [{ id: "a", priorityId: 1, actor: "backfill-priority" }]);
});

test("a High ticket gets the next slot down, not the top one", async () => {
  const db = fakeDb({ rows: [{ id: "a", worst_severity: "High" }] });
  const calls = [];
  const backfill = await loadBackfill({
    db,
    setGroupTicketPriority: async (id, priorityId, actor) => { calls.push({ id, priorityId, actor }); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }],
  });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 1, updated: 1, errors: 0 });
  assert.deepEqual(calls, [{ id: "a", priorityId: 2, actor: "backfill-priority" }]);
});

test("the query itself excludes tickets already carrying a priority-change audit entry", async () => {
  const db = fakeDb({ rows: [] }); // simulates the NOT EXISTS clause filtering it out
  const backfill = await loadBackfill({ db, cwPrioritiesBySort: async () => [{ id: 1 }] });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 0, updated: 0, errors: 0 });
  const select = db.calls[0];
  assert.match(select.sql, /NOT EXISTS/);
  assert.match(select.sql, /ticket\.priority\.changed/);
});

test("one ticket's ConnectWise call failing does not block the rest", async () => {
  const db = fakeDb({ rows: [{ id: "a", worst_severity: "Critical" }, { id: "b", worst_severity: "Critical" }] });
  const backfill = await loadBackfill({
    db,
    setGroupTicketPriority: async (id) => { if (id === "a") throw new Error("ConnectWise rejected the request"); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }],
  });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 2, updated: 1, errors: 1 });
});

test("no candidate tickets means no ConnectWise-bound calls at all", async () => {
  const db = fakeDb({ rows: [] });
  const backfill = await loadBackfill({ db });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 0, updated: 0, errors: 0 });
});

test("no ConnectWise connection configured means no db calls at all", async () => {
  const db = fakeDb({ rows: [] });
  const backfill = await loadBackfill({ db, savedConnection: async () => { throw new Error("not configured"); } });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 0, updated: 0, errors: 0 });
  assert.equal(db.calls.length, 0);
});

test("no ConnectWise priorities available leaves candidates checked but none updated", async () => {
  const db = fakeDb({ rows: [{ id: "a", worst_severity: "Critical" }] });
  const backfill = await loadBackfill({ db, cwPrioritiesBySort: async () => { throw new Error("ConnectWise unreachable"); } });
  const result = await backfill.backfillTicketPriority();
  assert.deepEqual(result, { checked: 1, updated: 0, errors: 0 });
});
