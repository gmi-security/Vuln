import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";

const sha256 = text => createHash("sha256").update(text).digest("hex");

export async function loadMigrations(directory) {
  const names = (await readdir(directory)).filter(name => /^\d{3}_[a-z0-9_]+\.sql$/.test(name)).sort();
  const migrations = [];
  for (const name of names) {
    const sql = await readFile(new URL(name, directory), "utf8");
    migrations.push({ name, sql, checksum: sha256(sql) });
  }
  return migrations;
}

export async function runMigrations(db, migrations) {
  const client = await db.connect();
  let inTransaction = false;
  try {
    await client.query("BEGIN");
    inTransaction = true;
    await client.query("SELECT pg_advisory_xact_lock(20260929, 1)");
    await client.query(`CREATE TABLE IF NOT EXISTS app_schema_migrations (
      name TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    const existing = await client.query("SELECT name, checksum FROM app_schema_migrations");
    const applied = new Map(existing.rows.map(row => [row.name, row.checksum]));
    const names = new Set();
    for (const migration of migrations) {
      if (!/^\d{3}_[a-z0-9_]+\.sql$/.test(migration.name) || names.has(migration.name)) {
        throw new Error(`Invalid or duplicate migration name: ${migration.name}`);
      }
      names.add(migration.name);
      if (sha256(migration.sql) !== migration.checksum) throw new Error(`Migration checksum mismatch: ${migration.name}`);
      if (applied.has(migration.name) && applied.get(migration.name) !== migration.checksum) {
        throw new Error(`Applied migration checksum mismatch: ${migration.name}`);
      }
    }
    for (const name of applied.keys()) {
      if (!names.has(name)) throw new Error(`Applied migration is missing from source: ${name}`);
    }
    const newlyApplied = [];
    for (const migration of migrations) {
      if (applied.has(migration.name)) continue;
      await client.query(migration.sql);
      await client.query("INSERT INTO app_schema_migrations (name, checksum) VALUES ($1, $2)", [migration.name, migration.checksum]);
      newlyApplied.push(migration.name);
    }
    await client.query("COMMIT");
    inTransaction = false;
    return newlyApplied;
  } catch (error) {
    if (inTransaction) await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
