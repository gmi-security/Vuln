// node --experimental-vm-modules --test tests/group-closure-validation.test.mjs
//
// Exercises validateClosedGroupTickets's orchestration in isolation (a fake
// db.query, mocked savedConnection/dashboardConnectionRevision/
// verifyAgainstCrowdStrike/cwDefaultOpenStatus/cwAddTicketNote/cwRequest):
// a closed ticket whose CVE is still open per CrowdStrike gets reopened with
// a note and marked still_open; a closed ticket that's genuinely fixed gets
// marked verified and is left alone in ConnectWise; a ticket already merged
// into a parent ticket in ConnectWise (detected from its own current status
// name) is flagged for manual separation instead of guessed at; a ticket
// with no CrowdStrike scope (stored-findings or no hostScope/board) is
// skipped; one ticket's ConnectWise call failing does not block the rest;
// and no candidates, no ConnectWise connection, or no CrowdStrike connection
// all mean no downstream calls at all.
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

function fakeDb({ closedRows, ticketRows = {} }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("FROM patch_group_ticket_requests") && sql.includes("closed=true")) return { rows: closedRows };
      if (sql.trim().startsWith("SELECT ticket_id,cw_target")) return { rows: [ticketRows[params[0]] ?? { ticket_id: null, cw_target: null }] };
      return { rows: [], rowCount: 1 }; // UPDATE / INSERT
    },
  };
}

async function loadValidation({ db, savedConnection, dashboardConnectionRevision, verifyAgainstCrowdStrike, cwDefaultOpenStatus, cwAddTicketNote, cwRequest, cwPrioritiesBySort, setGroupTicketPriority, syncTable }) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db, savedConnection: savedConnection ?? (async () => ({ revision: 7, value: {}, target: "cw-1" })) },
    "./elastic-dashboard-store": {
      dashboardConnectionRevision: dashboardConnectionRevision ?? (async () => 3),
      verifyAgainstCrowdStrike: verifyAgainstCrowdStrike ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./patch-group-ticket-store": {
      setGroupTicketPriority: setGroupTicketPriority ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./connectwise-client": {
      cwDefaultOpenStatus: cwDefaultOpenStatus ?? (async () => { throw new Error("not expected to be called"); }),
      cwAddTicketNote: cwAddTicketNote ?? (async () => { throw new Error("not expected to be called"); }),
      cwRequest: cwRequest ?? (async () => { throw new Error("not expected to be called"); }),
      cwPrioritiesBySort: cwPrioritiesBySort ?? (async () => []),
    },
    "./ticket-status-sync": { runWithConcurrency, syncTable: syncTable ?? (async () => ({ checked: 0, updated: 0, errors: 0 })) },
    "./elastic-vuln-server": { elasticVulnEnabled: () => false },
  })("lib/group-closure-validation.ts");
}

const baseRow = { id: "a", tenant_id: "tenant-1", routing: { boardId: 9 }, packet: { cves: ["CVE-2024-1"], hostScope: ["host-1"] }, worst_severity: "Critical" };

test("a closed ticket still vulnerable per CrowdStrike is reopened with a note and marked still_open", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  const noteCalls = []; const cwCalls = [];
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwAddTicketNote: async (connection, ticketId, text) => { noteCalls.push({ ticketId, text }); },
    cwRequest: async (connection, path, method, body) => { cwCalls.push({ path, method, body }); return {}; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  const patchCall = cwCalls.find((c) => c.method === "PATCH");
  assert.deepEqual(patchCall, { path: "/service/tickets/555", method: "PATCH", body: [{ op: "replace", path: "status/id", value: 42 }] });
  assert.equal(noteCalls.length, 1);
  assert.equal(noteCalls[0].ticketId, 555);
  assert.match(noteCalls[0].text, /still present on 1 host/);
});

test("ConnectWise rejecting the reopen with a merge-related error is flagged for manual separation, not treated as a generic failure", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  let notePosted = false; let priorityCalled = false;
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwRequest: async () => { throw new Error("ConnectWise returned HTTP 400. This ticket has been combined into a parent ticket and cannot be modified."); },
    cwAddTicketNote: async () => { notePosted = true; },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }],
    setGroupTicketPriority: async () => { priorityCalled = true; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 1, errors: 0 });
  assert.equal(notePosted, false);
  assert.equal(priorityCalled, false);
  const update = db.calls.find((c) => c.sql.includes("SET last_error"));
  assert.match(update.params[1], /combined into a parent ticket/);
  const audit = db.calls.find((c) => c.sql.includes("ticket.reopen.blocked_merged"));
  assert.ok(audit, "expected a ticket.reopen.blocked_merged audit entry");
});

test("a reopen failing for an unrelated ConnectWise error is a normal error, not needsManualUnmerge", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwRequest: async () => { throw new Error("ConnectWise returned HTTP 500. Internal error."); },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 1 });
});

test("a reopened Critical ticket has its priority reasserted to the top slot", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  const priorityCalls = [];
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwAddTicketNote: async () => {},
    cwRequest: async () => ({}),
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }],
    setGroupTicketPriority: async (id, priorityId, actor) => { priorityCalls.push({ id, priorityId, actor }); },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.deepEqual(priorityCalls, [{ id: "a", priorityId: 1, actor: "closure-validation" }]);
});

test("a reopened High ticket gets the next priority down, not the top one", async () => {
  const row = { ...baseRow, worst_severity: "High" };
  const db = fakeDb({ closedRows: [row], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  const priorityCalls = [];
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwAddTicketNote: async () => {},
    cwRequest: async () => ({}),
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }],
    setGroupTicketPriority: async (id, priorityId, actor) => { priorityCalls.push({ id, priorityId, actor }); },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.deepEqual(priorityCalls, [{ id: "a", priorityId: 2, actor: "closure-validation" }]);
});

test("no ConnectWise priorities available still reopens the ticket, just without touching priority", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  let priorityCalled = false;
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwAddTicketNote: async () => {},
    cwRequest: async () => ({}),
    cwPrioritiesBySort: async () => { throw new Error("ConnectWise unreachable"); },
    setGroupTicketPriority: async () => { priorityCalled = true; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.equal(priorityCalled, false);
});

test("a closed ticket that's genuinely fixed is marked verified and ConnectWise is never touched", async () => {
  const db = fakeDb({ closedRows: [baseRow] });
  let cwTouched = false;
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: [] }),
    cwDefaultOpenStatus: async () => { cwTouched = true; return { id: 1, name: "New" }; },
    cwRequest: async () => { cwTouched = true; return {}; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 1, needsManualUnmerge: 0, errors: 0 });
  assert.equal(cwTouched, false);
});

test("a ticket with no CrowdStrike scope (stored-findings) is skipped entirely", async () => {
  const row = { ...baseRow, packet: { source: "stored-findings", cves: ["CVE-2024-1"], hostScope: ["host-1"] } };
  const db = fakeDb({ closedRows: [row] });
  let verifyCalled = false;
  const validate = await loadValidation({ db, verifyAgainstCrowdStrike: async () => { verifyCalled = true; return { checkedAt: "x", stillOpenHosts: [] }; } });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.equal(verifyCalled, false);
});

test("a ticket with no board on its routing is skipped entirely", async () => {
  const row = { ...baseRow, routing: null };
  const db = fakeDb({ closedRows: [row] });
  let verifyCalled = false;
  const validate = await loadValidation({ db, verifyAgainstCrowdStrike: async () => { verifyCalled = true; return { checkedAt: "x", stillOpenHosts: [] }; } });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.equal(verifyCalled, false);
});

test("one ticket's ConnectWise call failing does not block the rest", async () => {
  const rowA = { ...baseRow, id: "a" };
  const rowB = { ...baseRow, id: "b" };
  const db = fakeDb({ closedRows: [rowA, rowB], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" }, b: { ticket_id: 556, cw_target: "cw-1" } } });
  const validate = await loadValidation({
    db,
    verifyAgainstCrowdStrike: async () => ({ checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }),
    cwDefaultOpenStatus: async (connection, boardId) => ({ id: 42, name: "New" }),
    cwAddTicketNote: async () => {},
    cwRequest: async (connection, path) => { if (path.includes("555")) throw new Error("ConnectWise rejected the request"); return {}; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 2, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 1 });
});

test("no closed candidate tickets means no CrowdStrike or ConnectWise calls at all", async () => {
  const db = fakeDb({ closedRows: [] });
  const validate = await loadValidation({ db });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
});

test("no ConnectWise connection configured means no db calls at all", async () => {
  const db = fakeDb({ closedRows: [] });
  const validate = await loadValidation({ db, savedConnection: async () => { throw new Error("not configured"); } });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.equal(db.calls.length, 0);
});

test("no CrowdStrike connection configured leaves candidates checked but nothing verified", async () => {
  const db = fakeDb({ closedRows: [baseRow] });
  let verifyCalled = false;
  const validate = await loadValidation({
    db,
    dashboardConnectionRevision: async () => null,
    verifyAgainstCrowdStrike: async () => { verifyCalled = true; return { checkedAt: "x", stillOpenHosts: [] }; },
  });
  const result = await validate.validateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 });
  assert.equal(verifyCalled, false);
});

test("syncAndValidateClosedGroupTickets refreshes ConnectWise status before validating, so a ticket closed since the last slow sync is still caught this pass", async () => {
  const db = fakeDb({ closedRows: [baseRow], ticketRows: { a: { ticket_id: 555, cw_target: "cw-1" } } });
  const calls = [];
  let syncArgs = null;
  const validate = await loadValidation({
    db,
    syncTable: async (...args) => { calls.push("sync"); syncArgs = args; return { checked: 3, updated: 1, errors: 0 }; },
    verifyAgainstCrowdStrike: async () => { calls.push("validate"); return { checkedAt: "2026-09-28T00:00:00.000Z", stillOpenHosts: ["host-1"] }; },
    cwDefaultOpenStatus: async () => ({ id: 42, name: "New" }),
    cwAddTicketNote: async () => {},
    cwRequest: async () => ({}),
  });
  const result = await validate.syncAndValidateClosedGroupTickets();
  assert.deepEqual(result, { checked: 1, reopened: 1, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0, synced: 1 });
  assert.deepEqual(calls, ["sync", "validate"]);
  assert.equal(syncArgs[1], "patch_group_ticket_requests");
  assert.deepEqual(syncArgs[4], { includeClosed: true, companyIds: ["CO-147284"] });
});

test("syncAndValidateClosedGroupTickets with no ConnectWise connection does nothing", async () => {
  const db = fakeDb({ closedRows: [] });
  const validate = await loadValidation({ db, savedConnection: async () => { throw new Error("not configured"); } });
  const result = await validate.syncAndValidateClosedGroupTickets();
  assert.deepEqual(result, { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0, synced: 0 });
});
