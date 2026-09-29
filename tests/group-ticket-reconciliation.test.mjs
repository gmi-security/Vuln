// node --experimental-vm-modules --test tests/group-ticket-reconciliation.test.mjs
//
// Exercises findUntrackedAtlasTickets in isolation (a fake db.query, mocked
// savedConnection/cwRequest): live Atlas tickets from ConnectWise that don't
// match any tracked ticket_id are returned; tracked ones are excluded;
// pagination across more than one page of results is followed; and no known
// Atlas routing (never learned yet) means an empty result with no
// ConnectWise call at all.
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

function fakeDb({ routing, trackedTicketIds = [], preparedDraftIds = [] }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("FROM patch_customer_routing")) return { rows: routing ? [routing] : [] };
      if (sql.includes("ticket_id IS NOT NULL AND cw_target")) return { rows: trackedTicketIds.map((id) => ({ ticket_id: id })) };
      if (sql.includes("state='prepared'") && sql.trim().startsWith("SELECT id")) return { rows: preparedDraftIds.includes(params[0]) ? [{ id: params[0] }] : [] };
      return { rows: [], rowCount: 1 }; // UPDATE / INSERT
    },
  };
}

async function loadReconciliation({ db, savedConnection, cwRequest }) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db, savedConnection: savedConnection ?? (async () => ({ revision: 7, value: {}, target: "cw-1" })) },
    "./connectwise-client": {
      cwRequest: cwRequest ?? (async () => { throw new Error("not expected to be called"); }),
      cwId: (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0,
      ticketUrl: (connection, id) => `https://example.myconnectwise.net/ticket/${id}`,
    },
  })("lib/group-ticket-reconciliation.ts");
}

const routing = { company_id: 55 };

test("a live Atlas ticket with no tracked row is returned as untracked", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async () => [{ id: 2656161, summary: "Patch CVE-2024-29059 | 1 affected devices", status: { name: "Closed Merged" }, closedFlag: true }],
  });
  const result = await reconciliation.findUntrackedAtlasTickets();
  assert.deepEqual(result, [{ id: 2656161, summary: "Patch CVE-2024-29059 | 1 affected devices", status: "Closed Merged", closed: true, url: "https://example.myconnectwise.net/ticket/2656161" }]);
});

test("a ticket already tracked by a ticket_id in our own table is excluded", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [2656161] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async () => [{ id: 2656161, summary: "Tracked", status: { name: "New" }, closedFlag: false }],
  });
  const result = await reconciliation.findUntrackedAtlasTickets();
  assert.deepEqual(result, []);
});

test("pagination across more than one page of ConnectWise results is followed", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [] });
  const pages = [
    Array.from({ length: 100 }, (_, i) => ({ id: i + 1, summary: "T", status: { name: "New" }, closedFlag: false })),
    [{ id: 101, summary: "Last page", status: { name: "New" }, closedFlag: false }],
  ];
  let calls = 0;
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async () => pages[calls++] ?? [],
  });
  const result = await reconciliation.findUntrackedAtlasTickets();
  assert.equal(result.length, 101);
  assert.equal(calls, 2);
});

test("no known Atlas routing yet means an empty result and no ConnectWise call at all", async () => {
  const db = fakeDb({ routing: undefined });
  let cwCalled = false;
  const reconciliation = await loadReconciliation({ db, cwRequest: async () => { cwCalled = true; return []; } });
  const result = await reconciliation.findUntrackedAtlasTickets();
  assert.deepEqual(result, []);
  assert.equal(cwCalled, false);
});

const UUID = "9cc45b19-bd25-47bf-8182-580b922ee041";

test("an untracked ticket whose attached CSV names a still-prepared draft is adopted", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], preparedDraftIds: [UUID] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "Patch CVE-2024-29059 | 1 affected devices", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-29059 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.adoptManualAtlasTickets();
  assert.deepEqual(result, { checked: 1, adopted: 1, noMatch: 0, errors: 0 });
  const update = db.calls.find((c) => c.sql.includes("SET state='created'"));
  assert.equal(update.params[0], UUID);
  assert.equal(update.params[1], 2656161);
  assert.equal(update.params[7], 55); // companyId
  assert.deepEqual(JSON.parse(update.params[8]), { companyId: 55, boardId: 9 });
  const audit = db.calls.find((c) => c.sql.includes("ticket.adopted"));
  assert.ok(audit, "expected a ticket.adopted audit entry");
});

test("an untracked ticket with no attachment UUID has no match, nothing written", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], preparedDraftIds: [UUID] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "New" }, closedFlag: false, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.adoptManualAtlasTickets();
  assert.deepEqual(result, { checked: 1, adopted: 0, noMatch: 1, errors: 0 });
  assert.equal(db.calls.some((c) => c.sql.includes("SET state='created'")), false);
});

test("a matched UUID whose draft is no longer state='prepared' (already superseded or already created) has no match", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], preparedDraftIds: [] }); // nothing currently in state='prepared'
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "New" }, closedFlag: false, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-29059 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.adoptManualAtlasTickets();
  assert.deepEqual(result, { checked: 1, adopted: 0, noMatch: 1, errors: 0 });
});

test("one ticket's ConnectWise lookup failing does not block the rest", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], preparedDraftIds: [UUID] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [
        { id: 1, summary: "T", status: { name: "New" }, closedFlag: false, board: { id: 9 }, company: { id: 55 } },
        { id: 2656161, summary: "T", status: { name: "New" }, closedFlag: false, board: { id: 9 }, company: { id: 55 } },
      ];
      if (path.includes("recordId=1")) throw new Error("ConnectWise unreachable");
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-29059 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.adoptManualAtlasTickets();
  assert.deepEqual(result, { checked: 2, adopted: 1, noMatch: 0, errors: 1 });
});
