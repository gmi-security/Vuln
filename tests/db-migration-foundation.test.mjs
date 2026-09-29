import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

const checksum = text => createHash("sha256").update(text).digest("hex");

test("migration runner applies pending migrations under one transaction and lock", async () => {
  const { runMigrations } = await import("../lib/db/migration-runner.mjs");
  const calls = [];
  const client = {
    query: async (sql, params) => {
      calls.push({ sql: String(sql), params });
      if (String(sql).includes("SELECT name, checksum FROM app_schema_migrations")) return { rows: [] };
      return { rows: [] };
    },
    release: () => calls.push({ sql: "RELEASE" }),
  };
  const applied = await runMigrations({ connect: async () => client }, [
    { name: "001_first.sql", sql: "SELECT 42", checksum: checksum("SELECT 42") },
  ]);
  assert.deepEqual(applied, ["001_first.sql"]);
  assert.equal(calls[0].sql, "BEGIN");
  assert.match(calls[1].sql, /pg_advisory_xact_lock/);
  assert.ok(calls.findIndex(c => c.sql === "SELECT 42") > calls.findIndex(c => c.sql.includes("app_schema_migrations")));
  assert.equal(calls.at(-2).sql, "COMMIT");
  assert.equal(calls.at(-1).sql, "RELEASE");
});

test("migration runner refuses a modified applied migration without executing it", async () => {
  const { runMigrations } = await import("../lib/db/migration-runner.mjs");
  const calls = [];
  const client = {
    query: async sql => {
      calls.push(String(sql));
      if (String(sql).includes("SELECT name, checksum FROM app_schema_migrations")) {
        return { rows: [{ name: "001_first.sql", checksum: "old" }] };
      }
      return { rows: [] };
    },
    release: () => {},
  };
  await assert.rejects(
    () => runMigrations({ connect: async () => client }, [
      { name: "001_first.sql", sql: "SELECT 42", checksum: checksum("SELECT 42") },
    ]),
    /checksum mismatch/i,
  );
  assert.ok(!calls.includes("SELECT 42"));
  assert.equal(calls.at(-1), "ROLLBACK");
});

test("migration runner skips an unchanged migration and rolls back failed SQL", async () => {
  const { runMigrations } = await import("../lib/db/migration-runner.mjs");
  const migration = { name: "001_first.sql", sql: "SELECT 42", checksum: checksum("SELECT 42") };
  const skipped = [];
  const skipClient = {
    query: async sql => {
      skipped.push(String(sql));
      if (String(sql).includes("SELECT name, checksum FROM app_schema_migrations")) return { rows: [{ name: migration.name, checksum: migration.checksum }] };
      return { rows: [] };
    },
    release: () => {},
  };
  assert.deepEqual(await runMigrations({ connect: async () => skipClient }, [migration]), []);
  assert.ok(!skipped.includes("SELECT 42"));

  const failed = [];
  const failClient = {
    query: async sql => {
      failed.push(String(sql));
      if (String(sql).includes("SELECT name, checksum FROM app_schema_migrations")) return { rows: [] };
      if (sql === "SELECT 42") throw new Error("database rejected migration");
      return { rows: [] };
    },
    release: () => failed.push("RELEASE"),
  };
  await assert.rejects(() => runMigrations({ connect: async () => failClient }, [migration]), /database rejected/);
  assert.deepEqual(failed.slice(-2), ["ROLLBACK", "RELEASE"]);
});

test("migration loader records a stable checksum for the checked-in SQL", async () => {
  const { loadMigrations } = await import("../lib/db/migration-runner.mjs");
  const migrations = await loadMigrations(new URL("../db/migrations/", import.meta.url));
  assert.equal(migrations[0].name, "001_core_storage.sql");
  assert.equal(migrations[0].checksum, checksum(migrations[0].sql));
  assert.ok(migrations[0].sql.includes("CREATE TABLE app_findings"));
});

test("snapshot inventory counts buckets without fetching JSONB payloads", async () => {
  const { collectSnapshotInventory } = await import("../lib/db/snapshot-inventory.mjs");
  const calls = [];
  const client = {
    query: async (sql, params) => {
      const statement = String(sql);
      calls.push({ statement, params });
      if (statement.includes("current_database()")) return { rows: [{ database_name: "gmi_vuln", role_name: "gmi_vuln", schema_name: "public", server_version: "18.0", max_connections: "100", database_bytes: "123456", can_create_schema_objects: true }] };
      if (statement.includes("FROM pg_class c")) return { rows: [{ schema_name: "public", table_name: "vuln_store", owner_name: "gmi_vuln", total_bytes: "1024" }] };
      if (statement.includes("to_regclass")) return { rows: [{ snapshot_table: "vuln_store", legacy_table: "vuln_snapshot", spotlight_table: null }] };
      if (statement.includes("SELECT key FROM vuln_store")) return { rows: [{ key: "findings:00" }, { key: "companies:00" }, { key: "meta" }] };
      if (statement.includes("data->'compensatingControls'")) return { rows: [{ controls: 4, aliases: 7 }] };
      if (statement.includes("jsonb_array_length")) return { rows: [{ items: params[0] === "findings:00" ? 123 : 2 }] };
      if (statement.includes("MAX(updated_at)")) return { rows: [{ updated_at: "2026-09-29T00:00:00.000Z" }] };
      return { rows: [] };
    },
  };
  const result = await collectSnapshotInventory(client);
  assert.equal(result.collections.findings, 123);
  assert.equal(result.collections.companies, 2);
  assert.equal(result.collections.compensatingControls, 4);
  assert.equal(result.collections.identityAliases, 7);
  assert.equal(result.bucketCount, 2);
  assert.equal(result.source, "sharded");
  assert.equal(result.updatedAt, "2026-09-29T00:00:00.000Z");
  assert.equal(result.spotlightTablePresent, false);
  assert.equal(result.database.name, "gmi_vuln");
  assert.equal(result.database.maxConnections, 100);
  assert.equal(result.database.bytes, 123456);
  assert.equal(result.database.canCreateSchemaObjects, true);
  assert.equal(result.tables[0].name, "vuln_store");
  assert.equal(result.tables[0].bytes, 1024);
  assert.ok(calls.every(c => !/SELECT\s+data\s+FROM\s+vuln_store/i.test(c.statement)));
});

test("snapshot inventory reports legacy-only state instead of a misleading empty store", async () => {
  const { collectSnapshotInventory } = await import("../lib/db/snapshot-inventory.mjs");
  const client = {
    query: async sql => {
      const statement = String(sql);
      if (statement.includes("to_regclass")) return { rows: [{ snapshot_table: "vuln_store", legacy_table: "vuln_snapshot", spotlight_table: null }] };
      if (statement.includes("SELECT key FROM vuln_store")) return { rows: [] };
      if (statement.includes("FROM vuln_snapshot WHERE id = 1")) return { rows: [{ companies: 2, findings: 10, assets: 5, scans: 1, folders: 0, controls: 0, aliases: 0, updated_at: "2026-09-29T01:00:00Z" }] };
      return { rows: [] };
    },
  };
  const result = await collectSnapshotInventory(client);
  assert.equal(result.source, "legacy");
  assert.equal(result.collections.findings, 10);
  assert.equal(result.updatedAt, "2026-09-29T01:00:00.000Z");
});

test("snapshot inventory reads the legacy row when the sharded table does not exist", async () => {
  const { collectSnapshotInventory } = await import("../lib/db/snapshot-inventory.mjs");
  const client = {
    query: async sql => {
      const statement = String(sql);
      if (statement.includes("to_regclass")) return { rows: [{ snapshot_table: null, legacy_table: "vuln_snapshot", spotlight_table: null }] };
      if (statement.includes("FROM vuln_snapshot WHERE id = 1")) return { rows: [{ companies: 1, findings: 2, assets: 0, scans: 0, folders: 0, controls: 0, aliases: 0, updated_at: "2026-09-29T01:00:00Z" }] };
      if (statement.includes("FROM vuln_store")) throw new Error("sharded table does not exist");
      return { rows: [] };
    },
  };
  const result = await collectSnapshotInventory(client);
  assert.equal(result.source, "legacy");
  assert.equal(result.collections.findings, 2);
});

test("inventory connection target excludes username, password and query parameters", async () => {
  const { safeConnectionTarget } = await import("../lib/db/connection-target.mjs");
  const target = safeConnectionTarget("postgresql://secret-user:secret-pass@db.example.com:25060/gmi_vuln?sslmode=require&token=secret");
  assert.deepEqual(target, { host: "db.example.com", port: "25060", database: "gmi_vuln" });
  assert.ok(!JSON.stringify(target).includes("secret"));
});

test("inventory reports completed Spotlight generation count and in-progress runs separately", async () => {
  const { collectSnapshotInventory } = await import("../lib/db/snapshot-inventory.mjs");
  const queries = [];
  const client = { query: async sql => {
    const statement = String(sql);
    queries.push(statement);
    if (statement.includes("to_regclass")) return { rows: [{ snapshot_table: null, legacy_table: null, spotlight_table: "spotlight_import_records", spotlight_current_table: "spotlight_import_current", spotlight_runs_table: "spotlight_import_runs" }] };
    if (statement.includes("FROM spotlight_import_current c")) return { rows: [{ tenant_key: "CO-147284", run_id: "run-done", status: "completed", active_record_count: "2127459", finished_at: "2026-09-29T18:00:00Z" }] };
    if (statement.includes("FROM spotlight_import_runs WHERE status = 'running'")) return { rows: [{ tenant_key: "CO-147284", run_id: "run-new", started_at: "2026-09-29T19:00:00Z" }] };
    return { rows: [] };
  } };
  const result = await collectSnapshotInventory(client);
  assert.equal(result.spotlight.active[0].records, 2127459);
  assert.equal(result.spotlight.running[0].runId, "run-new");
  assert.ok(queries.every(sql => !/SELECT\s+raw\s+FROM\s+spotlight_import_records/i.test(sql)));
});
