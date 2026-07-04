import { Pool } from "pg";

// Snapshot persistence. The whole in-memory store (companies, folders, scans,
// findings, assets, settings, counter) is serialized to a single JSONB row in
// Postgres. We hydrate it on cold start and flush it on a debounced timer, so
// all the existing in-memory logic keeps working unchanged and the data
// survives redeploys/restarts. Single App Platform instance, so no
// multi-writer concerns.

let pool: Pool | null = null;
let ready: Promise<void> | null = null;

function getPool(): Pool | null {
  if (!process.env.DATABASE_URL) return null;
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 3,
      // Fail fast if the DB is unreachable so hydration can fall back to
      // in-memory instead of hanging every request.
      connectionTimeoutMillis: 8000,
      idleTimeoutMillis: 30000,
    });
    pool.on("error", (err) => console.error("[persist] pool error:", err.message));
  }
  return pool;
}

// Reject if the DB op doesn't finish in time, so a slow/unreachable DB never
// blocks a request indefinitely.
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms),
    ),
  ]);
}

async function ensureTable(): Promise<void> {
  const p = getPool();
  if (!p) return;
  if (!ready) {
    ready = p
      .query(
        `CREATE TABLE IF NOT EXISTS vuln_snapshot (
           id INT PRIMARY KEY,
           data JSONB NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )`,
      )
      .then(() => undefined)
      .catch((err) => {
        // Don't cache a rejected promise — allow a later retry.
        ready = null;
        throw err;
      });
  }
  return ready;
}

export function persistenceEnabled(): boolean {
  return Boolean(process.env.DATABASE_URL);
}

export async function loadSnapshot(): Promise<unknown | null> {
  const p = getPool();
  if (!p) return null;
  await withTimeout(ensureTable(), 10000, "ensureTable");
  const res = await withTimeout(
    p.query("SELECT data FROM vuln_snapshot WHERE id = 1"),
    10000,
    "loadSnapshot",
  );
  return res.rows[0]?.data ?? null;
}

export async function saveSnapshot(data: unknown): Promise<void> {
  const p = getPool();
  if (!p) return;
  await withTimeout(ensureTable(), 10000, "ensureTable");
  await withTimeout(
    p.query(
      `INSERT INTO vuln_snapshot (id, data, updated_at)
       VALUES (1, $1, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [JSON.stringify(data)],
    ),
    10000,
    "saveSnapshot",
  );
}
