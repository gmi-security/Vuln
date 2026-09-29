import pg from "pg";
import { loadMigrations, runMigrations } from "../lib/db/migration-runner.mjs";

if (process.argv[2] !== "--apply") {
  throw new Error("Pass --apply to run versioned database migrations. This command changes schema.");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 1,
  connectionTimeoutMillis: 8000,
});
try {
  const migrations = await loadMigrations(new URL("../db/migrations/", import.meta.url));
  const applied = await runMigrations(pool, migrations);
  console.log(JSON.stringify({ applied }, null, 2));
} finally {
  await pool.end();
}
