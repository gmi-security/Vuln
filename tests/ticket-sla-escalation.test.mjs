// node --experimental-vm-modules --test tests/ticket-sla-escalation.test.mjs
//
// Exercises escalateTable in isolation (a fake db.query, a mocked cwRequest,
// a fixed most-urgent-first priority list, and the org's real per-severity
// SLA table) so this runs without a live Postgres or ConnectWise account: a
// ticket open past its own severity's SLA interval that hasn't already been
// escalated for that interval gets bumped exactly one priority level more
// urgent and audited; a ticket still within its severity's SLA is left
// alone; a ticket already at the most urgent priority just has its tier
// recorded without a ConnectWise call; an unrecognized current priority
// falls back to the least-urgent slot; and one ticket's PATCH failing does
// not block the rest. lib/vuln-sla.ts (the severity -> SLA-days mapping) is
// real code here, not a mock -- it has no runtime dependencies of its own.
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

// Real (tiny) implementation, not a mock -- matches lib/ticket-status-sync.ts's runWithConcurrency exactly.
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
      if (sql.trim().startsWith("SELECT")) return { rows };
      return { rows: [], rowCount: 1 }; // UPDATE / INSERT INTO ..._audit
    },
  };
}

const connection = { endpoint: "https://api-na.myconnectwise.net/v4_6_release/apis/3.0", companyId: "c", clientId: "id", publicKey: "pub", privateKey: "priv" };
// Most-urgent-first, matching cwPrioritiesBySort's contract.
const priorities = [
  { id: 10, name: "Priority 1 - Emergency" },
  { id: 11, name: "Priority 2 - High" },
  { id: 12, name: "Priority 3 - Medium" },
  { id: 13, name: "Priority 4 - Low" },
];
// The org's real, configurable per-severity SLA (Settings > SLA defaults).
const sla = { Critical: 7, High: 30, Medium: 60, Low: 90 };
const DAY = 86_400_000;
const daysAgo = (n) => new Date(Date.now() - n * DAY).toISOString();

async function loadWithConnectWise(handler) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => { throw new Error("not used by escalateTable"); }, savedConnection: async () => { throw new Error("not used by escalateTable"); } },
    "./connectwise-client": { cwRequest: handler, cwPrioritiesBySort: async () => { throw new Error("not used by escalateTable"); } },
    "./ticket-status-sync": { runWithConcurrency },
    "./elastic-vuln-server": { elasticVulnEnabled: () => false },
    "./store": { ensureHydrated: async () => { throw new Error("not used by escalateTable"); }, getSettings: () => { throw new Error("not used by escalateTable"); } },
  })("lib/ticket-sla-escalation.ts");
}

test("a Critical ticket past its 7-day SLA interval is bumped one priority level and audited", async () => {
  const calls = [];
  const escalation = await loadWithConnectWise(async (_conn, path, method, body) => { calls.push({ path, method, body }); return {}; });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(8), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: "Critical" }] });
  const result = await escalation.escalateTable(db, "patch_group_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 1, errors: 0 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "PATCH");
  assert.deepEqual(calls[0].body, [{ op: "replace", path: "priority/id", value: 10 }]); // moved from High (idx 1) to Emergency (idx 0)
  const update = db.calls.find((c) => c.sql.trim().startsWith("UPDATE"));
  assert.deepEqual(update.params, ["a", 10, "Priority 1 - Emergency", 1]);
  const audit = db.calls.find((c) => c.sql.includes("patch_group_ticket_audit"));
  assert.deepEqual(audit.params, ["a"]);
  assert.match(audit.sql, /'sla-escalation','ticket\.priority\.escalated'/);
});

test("a Low ticket well inside its 90-day SLA window is left alone", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(3), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: "Low" }] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 0, errors: 0 });
  assert.equal(called, false);
});

test("a High ticket past its 30-day SLA that's still just High isn't the same as Critical breaching at 7", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  // 10 days is well past Critical's 7-day SLA but nowhere near High's 30-day SLA.
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(10), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: "High" }] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 0, errors: 0 });
  assert.equal(called, false);
});

test("a ticket already at the most urgent priority just has its tier recorded, no ConnectWise call", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(40), ticket_priority_id: 10, ticket_sla_escalations: 0, worst_severity: "High" }] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 0, errors: 0 });
  assert.equal(called, false);
  const update = db.calls.find((c) => c.sql.trim().startsWith("UPDATE"));
  assert.deepEqual(update.params, ["a", 1]);
});

test("an unrecognized current priority falls back to the least-urgent slot and still escalates one step", async () => {
  const calls = [];
  const escalation = await loadWithConnectWise(async (_conn, path, method, body) => { calls.push({ path, method, body }); return {}; });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(8), ticket_priority_id: null, ticket_sla_escalations: 0, worst_severity: "Critical" }] });
  const result = await escalation.escalateTable(db, "patch_group_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 1, errors: 0 });
  assert.deepEqual(calls[0].body, [{ op: "replace", path: "priority/id", value: 12 }]); // Low (idx 3, fallback) -> Medium (idx 2)
});

test("a ticket with no CVE severity recorded falls back to the High SLA interval", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  // 10 days is past nothing under the High (30-day) fallback.
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(10), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: null }] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 0, errors: 0 });
  assert.equal(called, false);
});

test("a ticket already escalated once this run does not escalate again until the next SLA interval", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  const db = fakeDb({ rows: [{ id: "a", ticket_id: 1, prepared_at: daysAgo(65), ticket_priority_id: 11, ticket_sla_escalations: 1, worst_severity: "Medium" }] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 1, escalated: 0, errors: 0 });
  assert.equal(called, false);
});

test("one ticket's escalation failing does not stop the others", async () => {
  const escalation = await loadWithConnectWise(async (_conn, path) => {
    if (path.endsWith("/1")) throw new Error("ConnectWise rejected the change");
    return {};
  });
  const db = fakeDb({ rows: [
    { id: "a", ticket_id: 1, prepared_at: daysAgo(8), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: "Critical" },
    { id: "b", ticket_id: 2, prepared_at: daysAgo(8), ticket_priority_id: 11, ticket_sla_escalations: 0, worst_severity: "Critical" },
  ] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 2, escalated: 1, errors: 1 });
});

test("no open tickets means no ConnectWise calls at all", async () => {
  let called = false;
  const escalation = await loadWithConnectWise(async () => { called = true; return {}; });
  const db = fakeDb({ rows: [] });
  const result = await escalation.escalateTable(db, "patch_ticket_requests", "target", connection, priorities, sla);
  assert.deepEqual(result, { checked: 0, escalated: 0, errors: 0 });
  assert.equal(called, false);
});
