import pg from "pg";
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
      const runs = (await client.query(`
        SELECT id::text AS id, tenant_key, status, started_at, finished_at,
          LEFT(error, 500) AS error
        FROM spotlight_import_runs
        ORDER BY started_at DESC
        LIMIT 10
      `)).rows;
      const active = (await client.query(`
        SELECT tenant_key, run_id::text AS run_id, promoted_at
        FROM spotlight_import_current
        ORDER BY tenant_key
      `)).rows;
      await client.query("COMMIT");
      console.log(JSON.stringify({
        connectionTarget: safeConnectionTarget(process.env.DATABASE_URL),
        recentRuns: runs,
        active,
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
