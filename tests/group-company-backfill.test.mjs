// node --experimental-vm-modules --test tests/group-company-backfill.test.mjs
//
// Exercises backfillAppCompanyId in isolation (a fake db.query, a fake main
// store) -- the Atlas tenant-CID fallback it re-evaluates (customerFalconTenantIds
// / atlasFalconReviewPacket) is real code here, not a mock, since neither has
// any runtime dependencies of its own. Covers: a row whose tenant matches the
// currently-configured Atlas CID gets appCompanyId + companyName written back;
// a row whose tenant does not match is left alone; no ATLAS_CROWDSTRIKE_TENANT_IDS
// configured means no writes and the main store is never touched; and no
// candidate rows means no writes.
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

async function loadBackfill({ db, ensureHydrated, getCompany }) {
  return loader({
    "./patch-ticket-store": { patchTicketDatabase: async () => db },
    "./store": {
      ensureHydrated: ensureHydrated ?? (async () => { throw new Error("not expected to be called"); }),
      getCompany: getCompany ?? (() => { throw new Error("not expected to be called"); }),
    },
  })("lib/group-company-backfill.ts");
}

const ATLAS_CID = "6db760f628624eb68faceddee095b1a6";

test("a row whose tenant matches the configured Atlas CID gets appCompanyId and companyName written back", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeDb({ rows: [{ id: "a", tenant_id: ATLAS_CID, source: null }] });
    const backfill = await loadBackfill({ db, ensureHydrated: async () => {}, getCompany: () => ({ name: "Atlas Healthcare" }) });
    const result = await backfill.backfillAppCompanyId();
    assert.deepEqual(result, { updated: 1 });
    const update = db.calls.find((c) => c.sql.trim().startsWith("UPDATE"));
    assert.deepEqual(update.params, ["a", "CO-147284", "Atlas Healthcare"]);
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});

test("a row whose tenant does not match the configured CID is left alone", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeDb({ rows: [{ id: "a", tenant_id: "some-other-tenant-cid-000000000", source: null }] });
    const backfill = await loadBackfill({ db, ensureHydrated: async () => {}, getCompany: () => ({ name: "Atlas Healthcare" }) });
    const result = await backfill.backfillAppCompanyId();
    assert.deepEqual(result, { updated: 0 });
    assert.equal(db.calls.filter((c) => c.sql.trim().startsWith("UPDATE")).length, 0);
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});

test("no ATLAS_CROWDSTRIKE_TENANT_IDS configured means no writes and the main store is never touched", async () => {
  delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS;
  const db = fakeDb({ rows: [{ id: "a", tenant_id: ATLAS_CID, source: null }] });
  const backfill = await loadBackfill({ db });
  const result = await backfill.backfillAppCompanyId();
  assert.deepEqual(result, { updated: 0 });
});

test("no rows missing appCompanyId means no writes", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeDb({ rows: [] });
    const backfill = await loadBackfill({ db });
    const result = await backfill.backfillAppCompanyId();
    assert.deepEqual(result, { updated: 0 });
    assert.equal(db.calls.length, 1); // only the initial SELECT
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});

// backfillCustomerRouting exercises three distinct queries in sequence
// (existence check, existing-ticket lookup, seed insert), so it needs its
// own fake that dispatches by which one is running rather than one fixed
// canned SELECT response.
function fakeRoutingDb({ existingRouting = [], matchingTicket = [] }) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (sql.includes("FROM patch_customer_routing")) return { rows: existingRouting };
      if (sql.includes("FROM patch_group_ticket_requests")) return { rows: matchingTicket };
      return { rows: [], rowCount: 1 }; // INSERT
    },
  };
}

test("seeds routing from the most recently created matching ticket when nothing is known yet", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeRoutingDb({ existingRouting: [], matchingTicket: [{ company_id: 55, board_id: 9, team_id: null }] });
    const backfill = await loadBackfill({ db });
    const result = await backfill.backfillCustomerRouting();
    assert.deepEqual(result, { seeded: true });
    const insert = db.calls.find((c) => c.sql.trim().startsWith("INSERT"));
    assert.deepEqual(insert.params, ["CO-147284", 55, 9, null, "backfill-from-existing-ticket"]);
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});

test("never overwrites a routing that's already known", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeRoutingDb({ existingRouting: [{ x: 1 }], matchingTicket: [{ company_id: 55, board_id: 9, team_id: null }] });
    const backfill = await loadBackfill({ db });
    const result = await backfill.backfillCustomerRouting();
    assert.deepEqual(result, { seeded: false });
    assert.equal(db.calls.length, 1); // only the existence check -- never even looked for a ticket to seed from
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});

test("no ATLAS_CROWDSTRIKE_TENANT_IDS configured means nothing seeded", async () => {
  delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS;
  const db = fakeRoutingDb({ existingRouting: [], matchingTicket: [{ company_id: 55, board_id: 9, team_id: null }] });
  const backfill = await loadBackfill({ db });
  const result = await backfill.backfillCustomerRouting();
  assert.deepEqual(result, { seeded: false });
  assert.equal(db.calls.filter((c) => c.sql.trim().startsWith("INSERT")).length, 0);
});

test("no matching created ticket means nothing seeded", async () => {
  process.env.ATLAS_CROWDSTRIKE_TENANT_IDS = ATLAS_CID;
  try {
    const db = fakeRoutingDb({ existingRouting: [], matchingTicket: [] });
    const backfill = await loadBackfill({ db });
    const result = await backfill.backfillCustomerRouting();
    assert.deepEqual(result, { seeded: false });
  } finally { delete process.env.ATLAS_CROWDSTRIKE_TENANT_IDS; }
});
