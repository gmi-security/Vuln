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
  assert.ok(calls.some(call => call.sql.includes("SELECT active.started_at") && call.sql.includes("started_at >")));
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

test("first resumable run creates version two after retiring a legacy running attempt", async () => {
  const calls = [];
  const created = { id: "new-run", tenant_key: "CO-147284", phase: "discovering",
    query_cursor: "", hydration_cursor: "", discovered_count: "0", expected_count: null, hydrated_count: "0" };
  const client = { query: async sql => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT id, tenant_key, phase")) return { rows: [], rowCount: 0 };
    if (String(sql).includes("INSERT INTO spotlight_import_runs")) return { rows: [created], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).beginOrResumeSpotlightRun("CO-147284");
  assert.equal(run.id, "new-run");
  assert.equal(run.phase, "discovering");
  assert.ok(calls.some(sql => sql.includes("checkpoint_version, phase")));
  assert.ok(calls.some(sql => sql.includes("Interrupted before resumable checkpoint")));
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

test("terminal discovery checks distinct staged IDs against CrowdStrike total", async () => {
  const calls = [];
  const client = { query: async (sql, values) => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT phase, query_cursor"))
      return { rows: [{ phase: "discovering", query_cursor: "prior", discovered_count: "2" }], rowCount: 1 };
    if (String(sql).includes("COUNT(*) AS count FROM spotlight_import_ids"))
      return { rows: [{ count: "2" }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await assert.rejects(() => createSpotlightRecordStore(db).saveSpotlightIdPage(
    "run-1", "CO-147284", "prior", ["duplicate"], "", 3), /distinct|incomplete/i);
  assert.ok(calls.some(sql => sql.includes("COUNT(*) AS count FROM spotlight_import_ids")));
  assert.ok(calls.includes("ROLLBACK"));
  assert.ok(!calls.some(sql => sql.includes("UPDATE spotlight_import_runs SET")));
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
  const checkpointGuard = calls.find(call => call.sql.includes("AS advances"));
  assert.deepEqual(checkpointGuard.values, ["run-1", "CO-147284", "source-1"]);
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

test("resumable promotion moves the active pointer only after exact staged ID reconciliation", async () => {
  const calls = [];
  const client = { query: async sql => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT phase, expected_count, hydrated_count"))
      return { rows: [{ phase: "hydrating", expected_count: "2", hydrated_count: "2" }], rowCount: 1 };
    if (String(sql).includes("AS records") && String(sql).includes("spotlight_import_records"))
      return { rows: [{ ids: "2", records: "2", hosts: "1", missing: "0", extra: "0" }], rowCount: 1 };
    return { rows: [{ id: "run-1" }], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const result = await createSpotlightRecordStore(db).completeResumableSpotlightRun("run-1", "CO-147284");
  assert.deepEqual(result, { findingsImported: 2, hostsAffected: 1 });
  const pointer = calls.findIndex(sql => sql.includes("INSERT INTO spotlight_import_current"));
  assert.ok(pointer > calls.findIndex(sql => sql.includes("AS missing")));
  assert.ok(pointer < calls.findIndex(sql => sql.trim() === "COMMIT"));
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
  const removed = [], removedIds = [];
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
    if (statement.includes("DELETE FROM spotlight_import_ids")) removedIds.push(values[0]);
    return { rows: [], rowCount: 1 };
  } };
  const store = createSpotlightRecordStore(db);
  await store.pruneSpotlightRuns("CO-147284");
  assert.deepEqual(removed, ["run-interrupted", "run-interrupted"]);
  assert.deepEqual(removedIds, ["run-interrupted"]);
  assert.ok(!removed.includes("run-active"));
});

test("cleanup cannot delete a newer failed run that may still be resumed", async () => {
  let candidateQuery = "";
  const db = { query: async sql => {
    const statement = String(sql);
    if (statement.includes("SELECT run_id FROM spotlight_import_current"))
      return { rows: [{ run_id: "run-active" }], rowCount: 1 };
    if (statement.includes("FROM spotlight_import_runs") && statement.includes("status <> 'running'")) {
      candidateQuery = statement;
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 0 };
  } };
  await createSpotlightRecordStore(db).pruneSpotlightRuns("CO-147284");
  assert.match(candidateQuery, /started_at\s*</i);
});

// Partitioned discovery (checkpoint_version 3): several independent cursor
// walks (one per partition_key, e.g. status:'open' / status:'reopen') run
// concurrently instead of one sequential walk -- built after a real 2.1M-
// finding tenant showed sequential discovery alone would take hours.

test("a brand new partitioned run creates version three and one partition row per key", async () => {
  const calls = [];
  const created = { id: "new-run", phase: "discovering", hydration_cursor: "",
    discovered_count: "0", expected_count: null, hydrated_count: "0" };
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT id, phase, hydration_cursor")) return { rows: [], rowCount: 0 };
    if (String(sql).includes("INSERT INTO spotlight_import_runs")) return { rows: [created], rowCount: 1 };
    if (String(sql).includes("SELECT partition_key, query_cursor, discovered_count, done"))
      return { rows: [{ partition_key: "open", query_cursor: "", discovered_count: "0", done: false },
        { partition_key: "reopen", query_cursor: "", discovered_count: "0", done: false }], rowCount: 2 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).beginOrResumePartitionedSpotlightRun("CO-147284", ["open", "reopen"]);
  assert.equal(run.id, "new-run");
  assert.equal(run.phase, "discovering");
  assert.deepEqual(run.partitions.map(p => p.key), ["open", "reopen"]);
  assert.ok(run.partitions.every(p => !p.done && p.queryCursor === ""));
  const insertRun = calls.find(c => c.sql.includes("INSERT INTO spotlight_import_runs"));
  assert.ok(insertRun.sql.includes("checkpoint_version") && insertRun.values[0] !== undefined);
  assert.ok(calls.some(c => c.sql.includes("INSERT INTO spotlight_import_partitions")));
});

test("a partitioned run resumes existing per-partition cursors instead of restarting them", async () => {
  const existingRun = { id: "run-resume", phase: "discovering", hydration_cursor: "",
    discovered_count: "600", expected_count: null, hydrated_count: "0" };
  const calls = [];
  const client = { query: async (sql) => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT id, phase, hydration_cursor")) return { rows: [{ id: "run-resume" }], rowCount: 1 };
    if (String(sql).includes("UPDATE spotlight_import_runs") && String(sql).includes("RETURNING"))
      return { rows: [existingRun], rowCount: 1 };
    if (String(sql).includes("SELECT partition_key, query_cursor, discovered_count, done"))
      return { rows: [{ partition_key: "open", query_cursor: "page-400", discovered_count: "400", done: false },
        { partition_key: "reopen", query_cursor: "", discovered_count: "200", done: true }], rowCount: 2 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).beginOrResumePartitionedSpotlightRun("CO-147284", ["open", "reopen"]);
  assert.equal(run.id, "run-resume");
  assert.ok(!calls.some(sql => sql.includes("INSERT INTO spotlight_import_partitions")), "must not re-seed partitions on resume");
  const open = run.partitions.find(p => p.key === "open");
  assert.equal(open.queryCursor, "page-400");
  assert.equal(open.done, false);
  const reopen = run.partitions.find(p => p.key === "reopen");
  assert.equal(reopen.done, true);
});

test("savePartitionPage keeps the run discovering while another partition is still open", async () => {
  const calls = [];
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT query_cursor, discovered_count, done"))
      return { rows: [{ query_cursor: "old", discovered_count: "400", done: false }], rowCount: 1 };
    if (String(sql).includes("SELECT COUNT(*) AS count FROM spotlight_import_partitions") && String(sql).includes("done = false"))
      return { rows: [{ count: "1" }], rowCount: 1 }; // the other partition is still open
    if (String(sql).includes("SUM(discovered_count)")) return { rows: [{ total: "402" }], rowCount: 1 };
    if (String(sql).includes("UPDATE spotlight_import_runs") && String(sql).includes("RETURNING"))
      return { rows: [{ id: "run-1", phase: "discovering", hydration_cursor: "", discovered_count: "402", expected_count: null, hydrated_count: "0" }], rowCount: 1 };
    if (String(sql).includes("SELECT partition_key, query_cursor, discovered_count, done"))
      return { rows: [{ partition_key: "open", query_cursor: "", discovered_count: "402", done: true },
        { partition_key: "reopen", query_cursor: "mid", discovered_count: "200", done: false }], rowCount: 2 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).savePartitionPage("run-1", "CO-147284", "open", "old", ["source-1", "source-2"], "", 402);
  assert.equal(run.phase, "discovering", "must not flip to hydrating while another partition remains open");
  const runUpdate = calls.find(c => c.sql.includes("UPDATE spotlight_import_runs") && c.sql.includes("RETURNING"));
  assert.deepEqual(runUpdate.values.slice(0, 4), ["run-1", "CO-147284", "402", false]);
});

test("savePartitionPage flips the whole run to hydrating once the last open partition finishes", async () => {
  const calls = [];
  const client = { query: async (sql, values) => {
    calls.push({ sql: String(sql), values });
    if (String(sql).includes("SELECT query_cursor, discovered_count, done"))
      return { rows: [{ query_cursor: "mid", discovered_count: "200", done: false }], rowCount: 1 };
    if (String(sql).includes("SELECT COUNT(*) AS count FROM spotlight_import_partitions") && String(sql).includes("done = false"))
      return { rows: [{ count: "0" }], rowCount: 1 }; // this was the last open partition
    if (String(sql).includes("COUNT(*)::text AS count FROM spotlight_import_ids"))
      return { rows: [{ count: "602" }], rowCount: 1 };
    if (String(sql).includes("SUM(discovered_count)")) return { rows: [{ total: "602" }], rowCount: 1 };
    if (String(sql).includes("UPDATE spotlight_import_runs") && String(sql).includes("RETURNING"))
      return { rows: [{ id: "run-1", phase: "hydrating", hydration_cursor: "", discovered_count: "602", expected_count: "602", hydrated_count: "0" }], rowCount: 1 };
    if (String(sql).includes("SELECT partition_key, query_cursor, discovered_count, done"))
      return { rows: [{ partition_key: "open", query_cursor: "", discovered_count: "402", done: true },
        { partition_key: "reopen", query_cursor: "", discovered_count: "200", done: true }], rowCount: 2 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  const run = await createSpotlightRecordStore(db).savePartitionPage("run-1", "CO-147284", "reopen", "mid", ["source-3"], "", 200);
  assert.equal(run.phase, "hydrating");
  assert.equal(run.expectedCount, 602);
  const runUpdate = calls.find(c => c.sql.includes("UPDATE spotlight_import_runs") && c.sql.includes("RETURNING"));
  assert.deepEqual(runUpdate.values, ["run-1", "CO-147284", "602", true, 602]);
  // Regression guard for a real production error: "column expected_count is
  // of type bigint but expression is of type text". CASE WHEN $n THEN $m
  // ELSE NULL END cannot infer $m's type from an untyped NULL branch, so it
  // silently defaults to text -- Postgres only catches the mismatch at
  // EXECUTE time against the real bigint column, which this string-matching
  // mock can't reproduce. The explicit ::bigint/::boolean casts are the fix;
  // this only guards that they don't get refactored away.
  assert.match(runUpdate.sql, /discovered_count\s*=\s*\$3::bigint/);
  assert.match(runUpdate.sql, /CASE WHEN \$4::boolean THEN 'hydrating'/);
  assert.match(runUpdate.sql, /CASE WHEN \$4::boolean THEN \$5::bigint ELSE NULL END/);
});

test("savePartitionPage rejects a page whose partition checkpoint already moved on", async () => {
  const calls = [];
  const client = { query: async sql => {
    calls.push(String(sql));
    if (String(sql).includes("SELECT query_cursor, discovered_count, done"))
      return { rows: [{ query_cursor: "newer-than-expected", discovered_count: "400", done: false }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await assert.rejects(() => createSpotlightRecordStore(db).savePartitionPage(
    "run-1", "CO-147284", "open", "stale-cursor", ["source-1"], "next", null), /checkpoint changed/i);
  assert.ok(calls.some(sql => sql === "ROLLBACK"));
  assert.ok(!calls.some(sql => sql.includes("INSERT INTO spotlight_import_ids")));
});

test("savePartitionPage rejects a page for an already-done partition", async () => {
  const client = { query: async sql => {
    if (String(sql).includes("SELECT query_cursor, discovered_count, done"))
      return { rows: [{ query_cursor: "", discovered_count: "400", done: true }], rowCount: 1 };
    return { rows: [], rowCount: 1 };
  }, release: () => {} };
  const db = { query: async () => ({ rows: [], rowCount: 0 }), connect: async () => client };
  await assert.rejects(() => createSpotlightRecordStore(db).savePartitionPage(
    "run-1", "CO-147284", "open", "", ["source-1"], "next", null), /checkpoint changed/i);
});

test("resetPartitionCursor clears only the named partition's cursor, leaving it undone and other partitions untouched", async () => {
  const calls = [];
  const db = { query: async (sql, values) => { calls.push({ sql: String(sql), values }); return { rows: [], rowCount: 1 }; } };
  await createSpotlightRecordStore(db).resetPartitionCursor("run-1", "CO-147284", "open", "Saved Spotlight cursor rejected: Spotlight query 400: invalid after token");
  const reset = calls.find(c => c.sql.includes("UPDATE spotlight_import_partitions"));
  assert.ok(reset.sql.includes("query_cursor = ''"));
  assert.ok(reset.sql.includes("partition_key = $3"));
  assert.ok(reset.sql.includes("done = false"), "must only reset a partition still in progress, not a completed one");
  assert.deepEqual(reset.values, ["run-1", "CO-147284", "open"]);
});

test("getPartitionedRunCheckpoint reads the current state without acquiring a client or mutating anything", async () => {
  let connected = false;
  const db = { connect: async () => { connected = true; throw new Error("must not open a transaction for a read"); },
    query: async sql => {
      if (String(sql).includes("SELECT id, phase, hydration_cursor"))
        return { rows: [{ id: "run-1", phase: "hydrating", hydration_cursor: "source-99",
          discovered_count: "602", expected_count: "602", hydrated_count: "300" }], rowCount: 1 };
      if (String(sql).includes("SELECT partition_key, query_cursor, discovered_count, done"))
        return { rows: [{ partition_key: "open", query_cursor: "", discovered_count: "402", done: true },
          { partition_key: "reopen", query_cursor: "", discovered_count: "200", done: true }], rowCount: 2 };
      return { rows: [], rowCount: 0 };
    } };
  const run = await createSpotlightRecordStore(db).getPartitionedRunCheckpoint("run-1", "CO-147284");
  assert.equal(connected, false);
  assert.equal(run.phase, "hydrating");
  assert.equal(run.hydratedCount, 300);
  assert.equal(run.partitions.length, 2);
});

test("getPartitionedRunCheckpoint throws for an unknown run instead of returning an empty checkpoint", async () => {
  const db = { query: async sql => String(sql).includes("SELECT id, phase, hydration_cursor")
    ? { rows: [], rowCount: 0 } : { rows: [], rowCount: 0 } };
  await assert.rejects(() => createSpotlightRecordStore(db).getPartitionedRunCheckpoint("missing", "CO-147284"), /not found/i);
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
