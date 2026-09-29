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

function fakeDb({ routing, trackedTicketIds = [], preparedDraftIds = [], draftPackets = {}, abandonBlocked = new Set() }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("FROM patch_customer_routing")) return { rows: routing ? [routing] : [] };
      if (sql.includes("ticket_id IS NOT NULL AND cw_target")) return { rows: trackedTicketIds.map((id) => ({ ticket_id: id })) };
      if (sql.includes("state='prepared'") && sql.trim().startsWith("SELECT id")) return { rows: preparedDraftIds.includes(params[0]) ? [{ id: params[0] }] : [] };
      if (sql.trim().startsWith("SELECT packet, tenant_id")) { const row = draftPackets[params[0]]; return { rows: row ? [row] : [] }; }
      if (sql.includes("SET state='abandoned'")) return { rows: [], rowCount: abandonBlocked.has(params[0]) ? 0 : 1 };
      return { rows: [], rowCount: 1 }; // UPDATE / INSERT
    },
  };
}

class FakeDashboardError extends Error {}

async function loadReconciliation({ db, savedConnection, cwRequest, activeTicketedPairs, persistPreparedPatch, persistPreparedGroups, dashboardConnectionRevision, prepareConsolidation, preparePatchRequest }) {
  return loader({
    "./patch-ticket-store": {
      patchTicketDatabase: async () => db, savedConnection: savedConnection ?? (async () => ({ revision: 7, value: {}, target: "cw-1" })),
      activeTicketedPairs: activeTicketedPairs ?? (async () => new Set()),
      persistPreparedPatch: persistPreparedPatch ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./patch-group-ticket-store": { persistPreparedGroups: persistPreparedGroups ?? (async () => { throw new Error("not expected to be called"); }) },
    "./elastic-dashboard-store": {
      dashboardConnectionRevision: dashboardConnectionRevision ?? (async () => 3),
      prepareConsolidation: prepareConsolidation ?? (async () => { throw new Error("not expected to be called"); }),
      preparePatchRequest: preparePatchRequest ?? (async () => { throw new Error("not expected to be called"); }),
    },
    "./elastic-dashboard": { DashboardError: FakeDashboardError },
    "./connectwise-client": {
      cwRequest: cwRequest ?? (async () => { throw new Error("not expected to be called"); }),
      cwId: (v) => typeof v === "number" && Number.isSafeInteger(v) && v > 0,
      ticketUrl: (connection, id) => `https://example.myconnectwise.net/ticket/${id}`,
    },
  })("lib/group-ticket-reconciliation.ts");
}

const routing = { company_id: 55, board_id: 9 };

test("a live Atlas ticket with no tracked row is returned as untracked", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async () => [{ id: 2656161, summary: "Patch CVE-2024-29059 | 1 affected devices", status: { name: "Closed Merged" }, closedFlag: true }],
  });
  const result = await reconciliation.findUntrackedAtlasTickets();
  assert.deepEqual(result, [{ id: 2656161, summary: "Patch CVE-2024-29059 | 1 affected devices", status: "Closed Merged", closed: true, url: "https://example.myconnectwise.net/ticket/2656161" }]);
});

test("the ConnectWise query is scoped to the Atlas patch board and to summaries containing \"Patch \" -- not every ticket for the company", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [] });
  let sentConditions = "";
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => { sentConditions = new URL(`https://x${path}`).searchParams.get("conditions") ?? ""; return []; },
  });
  await reconciliation.findUntrackedAtlasTickets();
  assert.match(sentConditions, /company\/id=55/);
  assert.match(sentConditions, /board\/id=9/);
  assert.match(sentConditions, /summary contains "Patch "/);
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

const draftPacket = { packet: { cves: ["CVE-2024-1", "CVE-2024-2"] }, tenant_id: "tenant-abc" };

test("a closed untracked ticket whose draft resolves is abandoned and its CVEs are queued for a fresh consolidated ticket", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  let consolidationInput = null;
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
    prepareConsolidation: async (input) => { consolidationInput = input; return { groups: [] }; },
    persistPreparedGroups: async () => ["new-id"],
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 1, cvesReplaced: 2, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 });
  assert.deepEqual(consolidationInput, { cves: ["CVE-2024-1", "CVE-2024-2"], tenantId: "tenant-abc", appCompanyId: "CO-147284" });
  const update = db.calls.find((c) => c.sql.includes("SET state='abandoned'"));
  assert.equal(update.params[0], UUID);
  assert.equal(update.params[1], 2656161);
  const audit = db.calls.find((c) => c.sql.includes("ticket.abandoned"));
  assert.ok(audit, "expected a ticket.abandoned audit entry");
});

test("an untracked ticket that's still open in ConnectWise is left alone -- only closed ones are treated as lost", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "New" }, closedFlag: false, board: { id: 9 }, company: { id: 55 } }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 0, abandoned: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 });
  assert.equal(db.calls.some((c) => c.sql.includes("SET state='abandoned'")), false);
});

test("a single leftover CVE (no group to join) is drafted through the single-CVE flow for manual review", async () => {
  const singleCvePacket = { packet: { cves: ["CVE-2024-1"] }, tenant_id: "tenant-abc" };
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: singleCvePacket } });
  let patchInput = null;
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
    preparePatchRequest: async (input) => { patchInput = input; return { cve: "CVE-2024-1" }; },
    persistPreparedPatch: async () => "new-id",
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 1, cvesReplaced: 0, cvesNeedsReview: 1, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 });
  assert.deepEqual(patchInput, { cve: "CVE-2024-1", tenantId: "tenant-abc" });
});

test("CrowdStrike reporting nothing left to replace (already patched or already covered elsewhere) counts as covered, not an error", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
    prepareConsolidation: async () => { throw new FakeDashboardError("Every open/reopened finding for this CVE already has an active ticket in progress. No patch request was prepared."); },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 1, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 2, unresolved: 0, errors: 0 });
});

test("a genuine failure re-collecting from CrowdStrike is a normal error, not counted as already covered", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
    prepareConsolidation: async () => { throw new Error("ConnectWise unreachable"); },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 1, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 1 });
});

test("no CrowdStrike connection configured still abandons the ticket, but leaves replacement for later", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
    dashboardConnectionRevision: async () => null,
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 1, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 });
});

test("a ticket already abandoned or adopted by a concurrent pass (the update matches nothing) is left as unresolved, not double-counted", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket }, abandonBlocked: new Set([UUID]) });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 1, errors: 0 });
});

test("an untracked closed ticket with no resolvable draft origin is left completely untouched", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [] });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      if (path.startsWith("/service/tickets?")) return [{ id: 2656161, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      if (path.startsWith("/system/documents?")) return [];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 1, abandoned: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 1, errors: 0 });
  assert.equal(db.calls.some((c) => c.sql.includes("SET state='abandoned'")), false);
});

test("a closed untracked ticket that matches every other filter but isn't in the confirmed list of 36 is never touched", async () => {
  const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
  const reconciliation = await loadReconciliation({
    db,
    cwRequest: async (connection, path) => {
      // Some other closed, untracked, "Patch " ticket on the same board -- not one of the 36.
      if (path.startsWith("/service/tickets?")) return [{ id: 9999999, summary: "Patch CVE-2024-1 | 1 affected devices", status: { name: "Closed" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
      throw new Error(`unexpected path ${path}`);
    },
  });
  const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
  assert.deepEqual(result, { checked: 0, abandoned: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 });
  assert.equal(db.calls.some((c) => c.sql.includes("SELECT packet, tenant_id") || c.sql.includes("SET state='abandoned'")), false); // never even looked up its attachments or draft
});

test("every one of the 36 confirmed ticket numbers is accepted by the allowlist", async () => {
  const KNOWN_LOST_ATLAS_TICKET_IDS = [
    2655148, 2655170, 2655171, 2655172, 2655173, 2655174, 2655175,
    2655990, 2655991, 2655996, 2656104, 2656130,
    2656151, 2656152, 2656153, 2656154, 2656155, 2656156, 2656157, 2656158, 2656159,
    2656160, 2656161, 2656162, 2656163, 2656164, 2656165, 2656166, 2656167, 2656168, 2656169,
    2656170, 2656171, 2656172, 2656173, 2656174,
  ];
  assert.equal(new Set(KNOWN_LOST_ATLAS_TICKET_IDS).size, 36);
  for (const id of KNOWN_LOST_ATLAS_TICKET_IDS) {
    const db = fakeDb({ routing, trackedTicketIds: [], draftPackets: { [UUID]: draftPacket } });
    const reconciliation = await loadReconciliation({
      db,
      cwRequest: async (connection, path) => {
        if (path.startsWith("/service/tickets?")) return [{ id, summary: "T", status: { name: "Closed Merged" }, closedFlag: true, board: { id: 9 }, company: { id: 55 } }];
        if (path.startsWith("/system/documents?")) return [{ title: `CVE-2024-1 patch request ${UUID}` }];
        throw new Error(`unexpected path ${path}`);
      },
      prepareConsolidation: async () => ({ groups: [] }),
      persistPreparedGroups: async () => ["new-id"],
    });
    const result = await reconciliation.abandonAndReplaceUntrackedAtlasTickets();
    assert.equal(result.abandoned, 1, `ticket #${id} should have been abandoned`);
  }
});
