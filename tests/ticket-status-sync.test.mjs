// node --experimental-vm-modules --test tests/ticket-status-sync.test.mjs
//
// Exercises syncTable in isolation (a fake db.query, a mocked cwRequest) so
// this runs without a live Postgres or ConnectWise account: it must poll
// every open, previously-created ticket, write only the ones whose status
// actually changed, log an audit row exactly for those, keep going when one
// ticket's lookup fails, and never touch tickets outside the requested
// ConnectWise target.
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

// A minimal fake `db` matching the .query(sql, params) shape syncTable uses.
// `onSelect`/`onUpdate` decide the canned response per call.
function fakeDb({ rows, updateMatches = () => true }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.trim().startsWith("SELECT")) return { rows };
      if (sql.trim().startsWith("UPDATE")) return { rowCount: updateMatches(params) ? 1 : 0 };
      return { rows: [], rowCount: 0 }; // INSERT INTO ..._audit
    },
  };
}

const connection = { endpoint: "https://api-na.myconnectwise.net/v4_6_release/apis/3.0", companyId: "c", clientId: "id", publicKey: "pub", privateKey: "priv" };

async function loadWithConnectWise(handler) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => { throw new Error("not used by syncTable"); }, savedConnection: async () => { throw new Error("not used by syncTable"); } },
    "./connectwise-client": { cwRequest: handler, cwId: (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0 },
    "./elastic-vuln-server": { elasticVulnEnabled: () => false },
  })("lib/ticket-status-sync.ts");
}

test("changed tickets are written and audited; unchanged tickets are left alone", async () => {
  const sync = await loadWithConnectWise(async (_conn, path) => {
    if (path.endsWith("/1")) return { status: { name: "Closed" }, closedFlag: true }; // changed
    if (path.endsWith("/2")) return { status: { name: "Waiting" }, closedFlag: false }; // unchanged (see updateMatches)
    throw new Error("unexpected ticket id");
  });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1 }, { id: "b", ticket_id: 2 }], updateMatches: (params) => params[0] === "a" });
  const result = await sync.syncTable(db, "patch_ticket_requests", "target", connection);
  assert.deepEqual(result, { checked: 2, updated: 1, errors: 0 });
  const audits = db.calls.filter((c) => c.sql.includes("patch_ticket_audit"));
  assert.equal(audits.length, 1, "only the ticket that actually changed gets an audit row");
  assert.equal(audits[0].params[0], "a");
});

test("one ticket's lookup failing does not stop the others from syncing", async () => {
  const sync = await loadWithConnectWise(async (_conn, path) => {
    if (path.endsWith("/1")) throw new Error("ConnectWise timed out");
    return { status: { name: "Open" }, closedFlag: false };
  });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1 }, { id: "b", ticket_id: 2 }, { id: "c", ticket_id: 3 }] });
  const result = await sync.syncTable(db, "patch_group_ticket_requests", "target", connection);
  assert.deepEqual(result, { checked: 3, updated: 2, errors: 1 });
});

test("no open tickets means no ConnectWise calls at all", async () => {
  let called = false;
  const sync = await loadWithConnectWise(async () => { called = true; return {}; });
  const db = fakeDb({ rows: [] });
  const result = await sync.syncTable(db, "patch_ticket_requests", "target", connection);
  assert.deepEqual(result, { checked: 0, updated: 0, errors: 0 });
  assert.equal(called, false);
  assert.equal(db.calls.length, 1, "only the initial SELECT should run");
});

test("priority is captured on every sync pass, not just on an explicit check-status click", async () => {
  const sync = await loadWithConnectWise(async () => ({ status: { name: "Open" }, closedFlag: false, priority: { id: 11, name: "Priority 2 - High" } }));
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1 }] });
  await sync.syncTable(db, "patch_group_ticket_requests", "target", connection);
  const update = db.calls.find((c) => c.sql.trim().startsWith("UPDATE"));
  assert.deepEqual(update.params, ["a", "Open", false, 11, "Priority 2 - High"]);
});

test("the select is scoped to open, previously-created tickets on the current ConnectWise target", async () => {
  const sync = await loadWithConnectWise(async () => ({ status: { name: "Open" }, closedFlag: false }));
  const db = fakeDb({ rows: [] });
  await sync.syncTable(db, "patch_group_ticket_requests", "my-target", connection);
  const select = db.calls[0];
  assert.match(select.sql, /state='created'/);
  assert.match(select.sql, /closed=false/);
  assert.match(select.sql, /ticket_id IS NOT NULL/);
  assert.match(select.sql, /cw_target=\$1/);
  assert.deepEqual(select.params, ["my-target"]);
});
