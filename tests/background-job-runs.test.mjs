// node --experimental-vm-modules --test tests/background-job-runs.test.mjs
//
// Exercises recordJobRun/getJobRun against a fake db.query: a running/
// succeeded/failed write lands with the right shape and params, and no
// run ever recorded reads back as null rather than throwing.
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

function fakeDb({ row } = {}) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.trim().startsWith("SELECT")) return { rows: row ? [row] : [] };
      return { rows: [], rowCount: 1 };
    },
  };
}

async function loadModule(db) {
  return loader({ "./patch-ticket-store": { patchTicketDatabase: async () => db } })("lib/background-job-runs.ts");
}

test("recordJobRun writes a running row with no finished_at", async () => {
  const db = fakeDb();
  const mod = await loadModule(db);
  await mod.recordJobRun("close-and-recut", "running");
  const insert = db.calls[0];
  assert.match(insert.sql, /finished_at\)\s*\n\s*VALUES\(\$1,\$2,\$3::jsonb,\$4,now\(\),NULL\)/);
  assert.deepEqual(insert.params, ["close-and-recut", "running", null, null]);
});

test("recordJobRun writes a succeeded row with the result JSON and a finished timestamp", async () => {
  const db = fakeDb();
  const mod = await loadModule(db);
  await mod.recordJobRun("close-and-recut", "succeeded", { checked: 38, closed: 38 });
  const insert = db.calls[0];
  assert.match(insert.sql, /now\(\)\)/);
  assert.deepEqual(insert.params, ["close-and-recut", "succeeded", JSON.stringify({ checked: 38, closed: 38 }), null]);
});

test("recordJobRun writes a failed row with the error message", async () => {
  const db = fakeDb();
  const mod = await loadModule(db);
  await mod.recordJobRun("close-and-recut", "failed", undefined, "ConnectWise unreachable");
  const insert = db.calls[0];
  assert.deepEqual(insert.params, ["close-and-recut", "failed", null, "ConnectWise unreachable"]);
});

test("getJobRun returns null when the job has never run", async () => {
  const db = fakeDb({ row: undefined });
  const mod = await loadModule(db);
  const run = await mod.getJobRun("close-and-recut");
  assert.equal(run, null);
});

test("getJobRun maps a stored row back to a JobRun", async () => {
  const db = fakeDb({ row: { job: "close-and-recut", status: "succeeded", result: { closed: 38 }, error: null, started_at: "2026-09-29T00:00:00.000Z", finished_at: "2026-09-29T00:05:00.000Z" } });
  const mod = await loadModule(db);
  const run = await mod.getJobRun("close-and-recut");
  assert.deepEqual(run, { job: "close-and-recut", status: "succeeded", result: { closed: 38 }, error: null, startedAt: "2026-09-29T00:00:00.000Z", finishedAt: "2026-09-29T00:05:00.000Z" });
});
