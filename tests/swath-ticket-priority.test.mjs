// node --experimental-vm-modules --test tests/swath-ticket-priority.test.mjs
//
// Exercises reconcileTicketPriorityToSwath (lib/swath-ticket-priority.ts):
// a ticket with no human priority override gets its ConnectWise priority
// reconciled to its CVEs' worst (lowest-numbered) effective Swath; a ticket
// a real analyst has touched is never reconciled; a ticket with no risk
// data yet is left alone rather than guessed at; and one ticket's
// ConnectWise call failing does not block the rest.
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

function cwDb(ticketRows) {
  const calls = [];
  const query = async (sql, params) => { calls.push({ sql, params }); if (sql.includes("FROM patch_group_ticket_requests")) return { rows: ticketRows }; return { rows: [] }; };
  return { calls, query };
}
function riskDb(swathByTicket) {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes("min(effective_swath)")) {
      const tenantKey = params[0];
      return { rows: [{ swath: swathByTicket[tenantKey] ?? null }] };
    }
    return { rows: [] };
  };
  return { calls, query };
}

async function loadModule({ ticketRows, swathByTenant = {}, priorities = [{ id: 1, name: "Urgent" }, { id: 2, name: "High" }, { id: 3, name: "Medium" }, { id: 4, name: "Low" }], setPriority, savedConnectionOk = true }) {
  const cw = cwDb(ticketRows);
  const risk = riskDb(swathByTenant);
  const calls = [];
  const mod = await loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => cw, savedConnection: savedConnectionOk ? (async () => ({ revision: 1, value: {} })) : (async () => { throw new Error("not configured"); }) },
    "./patch-group-ticket-store": { setGroupTicketPriority: setPriority ?? (async (id, priorityId, actor) => { calls.push({ id, priorityId, actor }); }) },
    "./connectwise-client": { cwPrioritiesBySort: async () => priorities },
    "./group-ticket-priority": await loader()("lib/group-ticket-priority.ts"),
    "./risk-scoring-store": { riskScoringDatabase: async () => risk },
  })("lib/swath-ticket-priority.ts");
  return { mod, cw, risk, calls };
}

test("a ticket with no human priority override gets reconciled to its worst effective Swath", async () => {
  const { mod, calls } = await loadModule({
    ticketRows: [{ id: "t1", tenant_id: "tenant-1", cves: ["CVE-1", "CVE-2"], ticket_priority_id: 3 }],
    swathByTenant: { "tenant-1": 1 },
  });
  const result = await mod.reconcileTicketPriorityToSwath();
  assert.deepEqual(result, { checked: 1, updated: 1, errors: 0 });
  assert.deepEqual(calls, [{ id: "t1", priorityId: 1, actor: "risk-engine" }]);
});

test("the SQL excludes any ticket a real human has ever set priority on", async () => {
  const { mod, cw } = await loadModule({ ticketRows: [] });
  await mod.reconcileTicketPriorityToSwath();
  const select = cw.calls.find((c) => c.sql.includes("NOT EXISTS"));
  assert.match(select.sql, /a\.actor NOT IN/);
  assert.ok(select.params.includes("auto-create"));
  assert.ok(select.params.includes("backfill-priority"));
  assert.ok(select.params.includes("risk-engine"));
});

test("a ticket with no risk data yet for its CVEs is left untouched rather than guessed at", async () => {
  const { mod, calls } = await loadModule({
    ticketRows: [{ id: "t1", tenant_id: "tenant-1", cves: ["CVE-1"], ticket_priority_id: 3 }],
    swathByTenant: {}, // no entry -> min(effective_swath) is null
  });
  const result = await mod.reconcileTicketPriorityToSwath();
  assert.deepEqual(result, { checked: 1, updated: 0, errors: 0 });
  assert.equal(calls.length, 0);
});

test("a ticket already at the correct priority for its Swath is not re-set", async () => {
  const { mod, calls } = await loadModule({
    ticketRows: [{ id: "t1", tenant_id: "tenant-1", cves: ["CVE-1"], ticket_priority_id: 1 }],
    swathByTenant: { "tenant-1": 1 }, // Swath 1 -> priority id 1, already there
  });
  const result = await mod.reconcileTicketPriorityToSwath();
  assert.deepEqual(result, { checked: 1, updated: 0, errors: 0 });
  assert.equal(calls.length, 0);
});

test("one ticket's ConnectWise call failing does not block the rest", async () => {
  const { mod, calls } = await loadModule({
    ticketRows: [
      { id: "fails", tenant_id: "tenant-1", cves: ["CVE-1"], ticket_priority_id: 4 },
      { id: "ok", tenant_id: "tenant-1", cves: ["CVE-1"], ticket_priority_id: 4 },
    ],
    swathByTenant: { "tenant-1": 1 },
    setPriority: async (id) => { if (id === "fails") throw new Error("ConnectWise rejected the request"); calls.push({ id }); },
  });
  const result = await mod.reconcileTicketPriorityToSwath();
  assert.deepEqual(result, { checked: 2, updated: 1, errors: 1 });
});

test("no ConnectWise connection configured means no work at all", async () => {
  const { mod, calls } = await loadModule({ ticketRows: [], savedConnectionOk: false });
  const result = await mod.reconcileTicketPriorityToSwath();
  assert.deepEqual(result, { checked: 0, updated: 0, errors: 0 });
  assert.equal(calls.length, 0);
});
