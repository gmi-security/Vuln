// node --experimental-vm-modules tests/spotlight-record-store.test.mjs
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { SourceTextModule, SyntheticModule } from "node:vm";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../lib/spotlight-record-store.ts", import.meta.url), "utf8");
let runtimeDb;
const module = new SourceTextModule(ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText);
await module.link(async name => {
  if (name === "./persist") return new SyntheticModule(["applicationDatabase"], function () {
    this.setExport("applicationDatabase", () => runtimeDb);
  });
  const values = await import(name);
  return new SyntheticModule(Object.keys(values), function () {
    for (const key of Object.keys(values)) this.setExport(key, values[key]);
  });
});
await module.evaluate();
const { createSpotlightRecordStore } = module.namespace;

const row = (id, raw = { id }) => ({
  sourceId: id, tenantKey: "CO-147284", companyId: "CO-147284",
  hostname: "atlas-host", localIp: "10.0.0.1", externalIp: "", cve: "CVE-2026-1234",
  severity: "High", status: "open", description: "Issue", remediation: "Apply patch",
  observedAt: "2026-09-28T00:00:00.000Z", raw,
});

test("record batch preserves two CrowdStrike IDs on the same host and CVE with full payloads", async () => {
  const calls = [];
  const db = { query: async (sql, values) => {
    calls.push({ sql, values });
    return { rowCount: 2, rows: [] };
  } };
  const store = createSpotlightRecordStore(db);
  const stored = await store.writeSpotlightBatch("run-1", "CO-147284", [
    row("source-1", { id: "source-1", host_info: { local_ip: "10.0.0.1" } }),
    row("source-2", { id: "source-2", host_info: { local_ip: "10.0.0.1" } }),
  ]);
  assert.equal(stored, 2);
  const input = JSON.parse(calls.at(-1).values.find(value => typeof value === "string" && value.startsWith("[")));
  assert.deepEqual(input.map(item => item.source_id), ["source-1", "source-2"]);
  assert.equal(input[0].raw.host_info.local_ip, "10.0.0.1");
});

test("record batch rejects a missing source ID before writing", async () => {
  let queries = 0;
  const store = createSpotlightRecordStore({ query: async () => { queries++; return { rowCount: 0, rows: [] }; } });
  await assert.rejects(() => store.writeSpotlightBatch("run-1", "CO-147284", [row("")]), /source.*id/i);
  assert.equal(queries, 0);
});

test("resumable run reuses a failed hydration checkpoint instead of inserting a replacement", async () => {
  const calls = [];
  const checkpoint = { id: "run-resume", tenant_key: "CO-147284", phase: "hydrating",
    query_cursor: "last-page", hydration_cursor: "source-400", discovered_count: "800", expected_count: "800", hydrated_count: "400" };
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT id, tenant_key, phase")) return { rows: [checkpoint], rowCount: 1 };
    if (String(sql).includes("UPDATE spotlight_import_runs") && String(sql).includes("RETURNING")) return { rows: [checkpoint], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).beginOrResumeSpotlightRun("CO-147284");
  assert.equal(run.id, "run-resume");
  assert.equal(run.phase, "hydrating");
  assert.equal(run.hydratedCount, 400);
  assert.ok(!calls.some(call => call.sql.includes("INSERT INTO spotlight_import_runs")));
  assert.ok(calls.some(call => call.sql.trim() === "COMMIT"));
});

test("a second Spotlight worker cannot claim the same tenant lock", async () => {
  let released = false;
  const client = { query: async sql => String(sql).includes("pg_try_advisory_lock")
    ? { rows: [{ locked: false }], rowCount: 1 } : { rows: [], rowCount: 0 },
  release: () => { released = true; } };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await assert.rejects(() => createSpotlightRecordStore(db).acquireSpotlightWorkerLock("CO-147284"), /already running/i);
  assert.equal(released, true);
});

test("ID page and continuation cursor commit in one transaction", async () => {
  const calls = [];
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT phase, query_cursor")) return { rows: [{ phase: "discovering", query_cursor: "old", discovered_count: "400" }], rowCount: 1 };
    if (String(sql).includes("UPDATE spotlight_import_runs") && String(sql).includes("RETURNING")) return { rows: [{ discovered_count: "402", expected_count: null, phase: "discovering" }], rowCount: 1 };
    return { rows: [], rowCount: 2 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await createSpotlightRecordStore(db).saveSpotlightIdPage("run-1", "CO-147284", "old", ["source-1", "source-2"], "next", 800);
  const statements = calls.map(call => call.sql.trim());
  assert.equal(statements[0], "BEGIN");
  assert.ok(statements.some(sql => sql.includes("INSERT INTO spotlight_import_ids")));
  assert.ok(statements.some(sql => sql.includes("query_cursor = $")));
  assert.equal(statements.at(-1), "COMMIT");
});

test("hydrated records and their last ID commit in one transaction", async () => {
  const calls = [];
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT phase, hydration_cursor")) return { rows: [{ phase: "hydrating", hydration_cursor: "" }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await createSpotlightRecordStore(db).writeSpotlightHydrationBatch("run-1", "CO-147284", ["source-1"], [row("source-1")]);
  const statements = calls.map(call => call.sql.trim());
  assert.equal(statements[0], "BEGIN");
  assert.ok(statements.some(sql => sql.includes("INSERT INTO spotlight_import_records")));
  assert.ok(statements.some(sql => sql.includes("hydration_cursor = $")));
  assert.equal(statements.at(-1), "COMMIT");
});

test("resumable promotion rejects a missing ID even when record counts match", async () => {
  const calls = [];
  const client = { query: async sql => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT phase, expected_count, hydrated_count"))
      return { rows: [{ phase: "hydrating", expected_count: "2", hydrated_count: "2" }], rowCount: 1 };
    if (String(sql).includes("AS records") && String(sql).includes("spotlight_import_records"))
      return { rows: [{ ids: "2", records: "2", hosts: "1", missing: "1", extra: "1" }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await assert.rejects(() => createSpotlightRecordStore(db).completeResumableSpotlightRun("run-1", "CO-147284"), /count mismatch/i);
  assert.ok(calls.some(sql => sql.trim() === "ROLLBACK"));
  assert.ok(!calls.some(sql => sql.includes("INSERT INTO spotlight_import_current")));
});

test("starting a replacement run marks an interrupted prior run failed before inserting", async () => {
  const calls = [];
  const store = createSpotlightRecordStore({ query: async sql => {
    calls.push(String(sql));
    return { rows: [], rowCount: 1 };
  } });
  await store.beginSpotlightRun("CO-147284");
  const updateAt = calls.findIndex(sql => sql.includes("UPDATE spotlight_import_runs") && sql.includes("status = 'failed'"));
  const insertAt = calls.findIndex(sql => sql.includes("INSERT INTO spotlight_import_runs"));
  assert.ok(updateAt >= 0 && insertAt > updateAt);
});

test("promotion updates the completed run and active pointer in one transaction", async () => {
  const calls = [];
  const client = {
    query: async (sql) => {
      const statement = String(sql).trim().split(/\s+/).slice(0, 3).join(" ");
      calls.push(statement);
      return statement.startsWith("SELECT COUNT")
        ? { rowCount: 1, rows: [{ count: "2" }] }
        : { rowCount: 1, rows: [{ id: "run-1" }] };
    },
    release: () => { calls.push("RELEASE"); },
  };
  const store = createSpotlightRecordStore({ connect: async () => client, query: async () => ({ rows: [] }) });
  const completedCount = await store.completeSpotlightRun("run-1", "CO-147284", 2);
  assert.equal(completedCount, 2);
  assert.equal(calls[0], "BEGIN");
  assert.ok(calls[1].startsWith("SELECT COUNT"));
  assert.ok(calls[2].startsWith("UPDATE spotlight_import_runs"));
  assert.ok(calls[3].startsWith("INSERT INTO spotlight_import_current"));
  assert.equal(calls[4], "COMMIT");
  assert.equal(calls[5], "RELEASE");
});

test("promotion rejects a source ID shortfall and leaves the active pointer unchanged", async () => {
  const calls = [];
  const client = {
    query: async sql => {
      calls.push(String(sql));
      return { rowCount: 1, rows: [{ count: "1" }] };
    },
    release: () => {},
  };
  const store = createSpotlightRecordStore({ connect: async () => client, query: async () => ({ rows: [] }) });
  await assert.rejects(() => store.completeSpotlightRun("run-1", "CO-147284", 2), /count mismatch/i);
  assert.ok(calls.some(sql => sql === "ROLLBACK"));
  assert.ok(!calls.some(sql => sql.includes("INSERT INTO spotlight_import_current")));
});

test("cleanup removes interrupted generations in chunks while retaining the active generation", async () => {
  const removed = [];
  let deletes = 0;
  const db = { query: async (sql, values = []) => {
    const statement = String(sql);
    if (statement.includes("SELECT run_id FROM spotlight_import_current"))
      return { rows: [{ run_id: "run-active" }], rowCount: 1 };
    if (statement.includes("SELECT id FROM spotlight_import_runs"))
      return { rows: [{ id: "run-interrupted" }], rowCount: 1 };
    if (statement.includes("DELETE FROM spotlight_import_records")) {
      removed.push(values[0]);
      return { rows: [], rowCount: ++deletes === 1 ? 10_000 : 0 };
    }
    return { rows: [], rowCount: 1 };
  } };
  const store = createSpotlightRecordStore(db);
  await store.pruneSpotlightRuns("CO-147284");
  assert.deepEqual(removed, ["run-interrupted", "run-interrupted"]);
  assert.ok(!removed.includes("run-active"));
});

test("runtime Spotlight storage uses the established application database without the dashboard URL", async () => {
  const prior = process.env.ELASTIC_VULN_DATABASE_URL;
  delete process.env.ELASTIC_VULN_DATABASE_URL;
  const calls = [];
  runtimeDb = { query: async sql => { calls.push(String(sql)); return { rows: [], rowCount: 1 }; } };
  try {
    await module.namespace.beginSpotlightRun("CO-147284");
    assert.ok(calls.some(sql => sql.includes("CREATE TABLE IF NOT EXISTS spotlight_import_runs")));
    assert.ok(calls.some(sql => sql.includes("INSERT INTO spotlight_import_runs")));
  } finally {
    runtimeDb = undefined;
    if (prior === undefined) delete process.env.ELASTIC_VULN_DATABASE_URL;
    else process.env.ELASTIC_VULN_DATABASE_URL = prior;
  }
});
