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
      const checkpointSchema = (await client.query(`SELECT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = 'public'
          AND table_name = 'spotlight_import_runs' AND column_name = 'checkpoint_version'
      ) AS present`)).rows[0]?.present === true;
      const runs = (await client.query(checkpointSchema ? `
        SELECT id::text AS id, tenant_key, status, phase, checkpoint_version,
          discovered_count::text AS discovered_count,
          expected_count::text AS expected_count,
          hydrated_count::text AS hydrated_count,
          query_cursor <> '' AS has_query_cursor,
          hydration_cursor <> '' AS has_hydration_cursor,
          started_at, finished_at, LEFT(error, 500) AS error
        FROM spotlight_import_runs ORDER BY started_at DESC LIMIT 10
      ` : `
        SELECT id::text AS id, tenant_key, status, started_at, finished_at,
          LEFT(error, 500) AS error
        FROM spotlight_import_runs ORDER BY started_at DESC LIMIT 10
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
