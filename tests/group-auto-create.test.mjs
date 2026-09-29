// node --experimental-vm-modules --test tests/group-auto-create.test.mjs
//
// Exercises autoCreateHighSeverityTickets's orchestration in isolation (a
// fake db.query for the eligible-drafts/routing lookups, and mocked
// reviewGroupTicket/readGroupTicket/createGroupTicket/setGroupTicketPriority/
// cwPrioritiesBySort so this runs without a live Postgres or ConnectWise
// account): a Critical/High draft for a customer with a known-good routing
// gets auto-approved and auto-created; a draft for a customer with no
// routing yet is left alone, never guessed; a draft for a customer outside
// the pilot scope is left alone even with a known routing; one draft failing
// does not block the rest; no eligible drafts or no ConnectWise connection
// means no calls at all; and a successfully created ticket gets its
// ConnectWise priority set to match its severity (Critical -> the top
// priority, High -> the next one down), but never at the cost of the create
// count -- missing priorities or a ticket id that never confirms just skips
// that step silently.
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

function fakeDb({ eligible, routings }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("FROM patch_group_ticket_requests")) return { rows: eligible };
      if (sql.includes("FROM patch_customer_routing")) return { rows: routings };
      return { rows: [] };
    },
  };
}

async function loadAutoCreate({ db, savedConnection, reviewGroupTicket, readGroupTicket, createGroupTicket, setGroupTicketPriority, cwPrioritiesBySort }) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db, savedConnection: savedConnection ?? (async () => ({ revision: 7 })) },
    "./patch-group-ticket-store": {
      reviewGroupTicket: reviewGroupTicket ?? (async () => { throw new Error("not expected to be called"); }),
      readGroupTicket: readGroupTicket ?? (async () => { throw new Error("not expected to be called"); }),
      createGroupTicket: createGroupTicket ?? (async () => { throw new Error("not expected to be called"); }),
      setGroupTicketPriority: setGroupTicketPriority ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./ticket-status-sync": { runWithConcurrency },
    "./elastic-vuln-server": { elasticVulnEnabled: () => false },
    "./connectwise-client": { cwPrioritiesBySort: cwPrioritiesBySort ?? (async () => []) },
  })("lib/group-auto-create.ts");
}

test("a Critical draft with a known routing is auto-approved and auto-created", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const calls = { review: [], read: [], create: [] };
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async (id, action, actor) => { calls.review.push({ id, action, actor }); },
    readGroupTicket: async (id, withPacket) => { calls.read.push({ id, withPacket }); return { group: { ticketTitle: "T", ticketBody: "B" } }; },
    createGroupTicket: async (id, value, actor) => { calls.create.push({ id, value, actor }); },
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.deepEqual(calls.review, [{ id: "a", action: "approve", actor: "auto-create" }]);
  assert.deepEqual(calls.create, [{ id: "a", value: { routing: { companyId: 55, boardId: 9 }, title: "T", body: "B", connectionRevision: 7 }, actor: "auto-create" }]);
});

test("a draft for a customer with no known routing yet is left alone -- never guessed", async () => {
  const db = fakeDb({ eligible: [{ id: "a", app_company_id: "CO-147284" }], routings: [] });
  let called = false;
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => { called = true; },
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 0, errors: 0 });
  assert.equal(called, false);
});

test("a draft for a customer outside the pilot scope is left alone even with a known routing", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-999999" }],
    routings: [{ app_company_id: "CO-999999", company_id: 55, board_id: 9, team_id: null }],
  });
  let called = false;
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => { called = true; },
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 0, errors: 0 });
  assert.equal(called, false);
});

test("one draft failing does not block the others", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284" }, { id: "b", app_company_id: "CO-147284" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: async () => ({ group: { ticketTitle: "T", ticketBody: "B" } }),
    createGroupTicket: async (id) => { if (id === "a") throw new Error("ConnectWise rejected the request"); },
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 2, created: 1, errors: 1 });
});

test("no eligible drafts means no ConnectWise-bound calls at all", async () => {
  const db = fakeDb({ eligible: [], routings: [] });
  const autoCreate = await loadAutoCreate({ db });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 0, created: 0, errors: 0 });
});

test("no ConnectWise connection configured means no db calls at all", async () => {
  const db = fakeDb({ eligible: [], routings: [] });
  const autoCreate = await loadAutoCreate({ db, savedConnection: async () => { throw new Error("not configured"); } });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 0, created: 0, errors: 0 });
  assert.equal(db.calls.length, 0);
});

// readGroupTicket is reused for two different purposes here: once (with
// withPacket=true) to read the packet's title/body before creation, and then
// repeatedly (no second arg) by waitForTicketId polling for a confirmed
// ticket id -- mirrors the real function's two call shapes.
function readGroupTicketDualMode({ ticketId, state }) {
  return async (id, withPacket) =>
    withPacket ? { group: { ticketTitle: "T", ticketBody: "B" } } : { request: { ticketId, state } };
}

test("a Critical ticket gets ConnectWise's top priority set immediately after creation", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "Critical" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const priorityCalls = [];
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: 999, state: "created" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async (id, priorityId, actor) => { priorityCalls.push({ id, priorityId, actor }); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }, { id: 3, name: "Medium" }],
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.deepEqual(priorityCalls, [{ id: "a", priorityId: 1, actor: "auto-create" }]);
});

test("a High ticket gets the next priority down, not the top one", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "High" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const priorityCalls = [];
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: 999, state: "created" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async (id, priorityId, actor) => { priorityCalls.push({ id, priorityId, actor }); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }, { id: 3, name: "Medium" }],
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.deepEqual(priorityCalls, [{ id: "a", priorityId: 2, actor: "auto-create" }]);
});

test("a High ticket clamps to the only priority available when the board has just one", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "High" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const priorityCalls = [];
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: 999, state: "created" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async (id, priorityId, actor) => { priorityCalls.push({ id, priorityId, actor }); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Only" }],
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.deepEqual(priorityCalls, [{ id: "a", priorityId: 1, actor: "auto-create" }]);
});

test("no ConnectWise priorities available never blocks the ticket from counting as created", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "Critical" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  let priorityCalled = false;
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: 999, state: "created" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async () => { priorityCalled = true; },
    cwPrioritiesBySort: async () => { throw new Error("ConnectWise unreachable"); },
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.equal(priorityCalled, false);
  const update = db.calls.find((c) => c.sql.includes("SET last_error"));
  assert.deepEqual(update.params, ["a", "Ticket created, but couldn't fetch ConnectWise priorities to assert Critical: ConnectWise unreachable. The next priority backfill pass will retry."]);
});

test("a ticket id that never confirms leaves priority unset without failing the create count", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "Critical" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  let priorityCalled = false;
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: null, state: "failed" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async () => { priorityCalled = true; },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }],
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  assert.equal(priorityCalled, false);
  const update = db.calls.find((c) => c.sql.includes("SET last_error"));
  assert.match(update.params[1], /didn't appear within 60s to assert Critical priority/);
});

test("a priority-setting failure after ticket creation is recorded on the row instead of vanishing silently", async () => {
  const db = fakeDb({
    eligible: [{ id: "a", app_company_id: "CO-147284", worst_severity: "Critical" }],
    routings: [{ app_company_id: "CO-147284", company_id: 55, board_id: 9, team_id: null }],
  });
  const autoCreate = await loadAutoCreate({
    db,
    reviewGroupTicket: async () => {},
    readGroupTicket: readGroupTicketDualMode({ ticketId: 999, state: "created" }),
    createGroupTicket: async () => {},
    setGroupTicketPriority: async () => { throw new Error("ConnectWise rejected the request"); },
    cwPrioritiesBySort: async () => [{ id: 1, name: "Urgent" }],
  });
  const result = await autoCreate.autoCreateHighSeverityTickets();
  // The ticket itself was created successfully -- a priority failure must
  // never turn that into an "error" the way a failed creation would.
  assert.deepEqual(result, { checked: 1, created: 1, errors: 0 });
  const update = db.calls.find((c) => c.sql.includes("SET last_error"));
  assert.deepEqual(update.params, ["a", "Ticket created, but asserting Critical priority failed: ConnectWise rejected the request"]);
});
