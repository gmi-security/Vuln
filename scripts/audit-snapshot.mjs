import pg from "pg";
import { auditLegacyBuckets } from "../lib/db/legacy-snapshot-audit.mjs";
import { safeConnectionTarget } from "../lib/db/connection-target.mjs";

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1,
  connectionTimeoutMillis: 8000,
});
try {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      const exists = (await client.query("SELECT to_regclass('public.vuln_store')::text AS table_name")).rows[0]?.table_name;
      if (!exists) throw new Error("The sharded vuln_store table is required for this audit.");
      const keys = (await client.query("SELECT key FROM vuln_store ORDER BY key")).rows.map(row => row.key);
      async function* buckets() {
        for (const key of keys) {
          const row = (await client.query("SELECT data FROM vuln_store WHERE key = $1", [key])).rows[0];
          if (!row) throw new Error(`Snapshot bucket disappeared during audit: ${key}`);
          yield { key, data: row.data };
        }
      }
      const report = await auditLegacyBuckets(buckets());
      const updatedAt = (await client.query("SELECT MAX(updated_at) AS updated_at FROM vuln_store")).rows[0]?.updated_at;
      await client.query("COMMIT");
      console.log(JSON.stringify({
        connectionTarget: safeConnectionTarget(process.env.DATABASE_URL),
        snapshotUpdatedAt: updatedAt == null ? null : new Date(updatedAt).toISOString(),
        ...report,
      }, null, 2));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    }
  } finally {
    client.release();
  }
} finally {
  await pool.end();
}
