import { Pool } from "pg";

// Snapshot persistence. The whole in-memory store (companies, folders, scans,
// findings, assets, settings, counter) is serialized to a single JSONB row in
// Postgres. We hydrate it on cold start and flush it on a debounced timer, so
// all the existing in-memory logic keeps working unchanged and the data
// survives redeploys/restarts. Single App Platform instance, so no
// multi-writer concerns.

let pool: Pool | null = null;
let ready: Promise<void> | null = null;

// Detect common misconfigurations in DATABASE_URL.
function diagnoseDatabaseUrl(url: string): string | null {
  if (!url) return "DATABASE_URL is not set.";
  // DO private VPC hostnames have a "private-" prefix — unreachable from
  // App Platform without VPC peering. Public hostnames have no "private-" prefix.
  if (/\/\/private-/.test(url) && url.includes(".db.ondigitalocean.com")) {
    return "DATABASE_URL uses the private VPC hostname ('private-' prefix). Use the public hostname from the DigitalOcean database dashboard (Connection Details → Public Network).";
  }
  if (!url.startsWith("postgres://") && !url.startsWith("postgresql://")) {
    return `DATABASE_URL does not look like a Postgres URL (got: ${url.slice(0, 30)}…).`;
  }
  return null;
}

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
    pool.on("error", (err) => {
      console.error("[persist] pool error:", err.message);
      // Reset the cached pool on fatal errors so the next getPool() call
      // creates a fresh one that can re-resolve a recovered hostname.
      pool = null;
      ready = null;
    });
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

// Explicit connectivity probe: connect, run SELECT 1, return ok/error.
export async function pingDb(): Promise<{ ok: boolean; error?: string; hint?: string }> {
  const url = process.env.DATABASE_URL ?? "";
  const configHint = diagnoseDatabaseUrl(url);
  if (!url) return { ok: false, error: "DATABASE_URL is not set.", hint: configHint ?? undefined };
  const p = getPool();
  if (!p) return { ok: false, error: "Could not create connection pool.", hint: configHint ?? undefined };
  try {
    await withTimeout(p.query("SELECT 1"), 8000, "ping");
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      hint: configHint ?? "Check that DATABASE_URL in DigitalOcean uses the PUBLIC connection string (Connection Details → Public Network).",
    };
  }
}

export async function snapshotMeta(): Promise<{ updatedAt: string | null }> {
  const p = getPool();
  if (!p) return { updatedAt: null };
  try {
    await withTimeout(ensureTable(), 10000, "ensureTable");
    const res = await withTimeout(
      p.query("SELECT updated_at FROM vuln_snapshot WHERE id = 1"),
      10000,
      "snapshotMeta",
    );
    return { updatedAt: res.rows[0]?.updated_at ?? null };
  } catch {
    return { updatedAt: null };
  }
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
