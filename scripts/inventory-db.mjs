import pg from "pg";
import { safeConnectionTarget } from "../lib/db/connection-target.mjs";
import { collectSnapshotInventory } from "../lib/db/snapshot-inventory.mjs";

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
    const inventory = await collectSnapshotInventory(client);
    console.log(JSON.stringify({ connectionTarget: safeConnectionTarget(process.env.DATABASE_URL), ...inventory }, null, 2));
  } finally {
    client.release();
  }
} finally {
  await pool.end();
}
