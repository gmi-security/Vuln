import { Pool } from "pg";
import { createHash } from "node:crypto";

// Snapshot persistence. The in-memory store (companies, folders, scans,
// findings, assets, settings, counter) is serialized by store.ts and flushed
// here on a debounced timer. Storage is SHARDED across many rows in
// vuln_store (key TEXT PRIMARY KEY, data JSONB): each collection is split
// into a fixed number of hash buckets so no single JSONB value grows without
// bound (Postgres caps a jsonb value at ~255MB and the findings set alone is
// heading there), and unchanged buckets are skipped on every flush via a
// per-key content hash, so steady-state writes touch only the rows that
// actually changed. Single App Platform instance and store.ts serializes all
// flushes through one in-flight promise chain, so no multi-writer concerns —
// the in-process hash cache below is therefore authoritative.

let pool: Pool | null = null;
let ready: Promise<void> | null = null;

// Last successfully COMMITTED content hash per vuln_store key. Empty after a
// process boot (or dev-mode module reload), so the first save rewrites every
// row — correct and cheap enough. Only updated after a successful commit so a
// failed transaction retries every changed row on the next flush.
const lastWrittenHashes = new Map<string, string>();

// --- sharding layout ---------------------------------------------------------
// Bucket counts are FROZEN constants: the bucket for an id is
// sha1(id) % count, so changing a count would strand data in rows that
// loadSnapshot still reads but saveSnapshot no longer writes. Add a new
// collection if needed; never renumber an existing one.
const COLLECTION_BUCKETS: Record<string, number> = {
  findings: 64,
  assets: 16,
  scans: 8,
  companies: 1,
  folders: 1,
};

// Row holding every top-level key that isn't a sharded collection
// (settings, counter, and anything future store.ts versions add).
const META_KEY = "meta";

function bucketKey(collection: string, index: number): string {
  return `${collection}:${String(index).padStart(2, "0")}`;
}

function sha1Hex(text: string): string {
  return createHash("sha1").update(text).digest("hex");
}

// Stable id -> bucket assignment. Uses sha1 so the distribution is uniform
// and identical across processes/restarts.
function bucketOf(id: string, buckets: number): number {
  if (buckets <= 1) return 0;
  return createHash("sha1").update(id).digest().readUInt32BE(0) % buckets;
}

// serializeStore() emits collections as Map entry tuples: [id, object].
// Accept plain objects with a string `id` too, so a future serializer change
// doesn't silently break bucketing. Anything else hashes by its JSON, which
// is stable for a given item.
function itemId(item: unknown): string {
  if (Array.isArray(item) && typeof item[0] === "string") return item[0];
  if (
    item !== null &&
    typeof item === "object" &&
    typeof (item as { id?: unknown }).id === "string"
  ) {
    return (item as { id: string }).id;
  }
  return JSON.stringify(item) ?? "null";
}

// Split the serialized store into its vuln_store rows. ALWAYS emits every
// bucket key for every known collection (a missing/empty collection becomes
// [] in each of its buckets) plus the meta row — so a collection that
// shrinks or vanishes overwrites its old rows with empty arrays instead of
// leaving stale data behind. The key set is thus constant.
function shardSnapshot(data: Record<string, unknown>): Map<string, unknown> {
  const rows = new Map<string, unknown>();
  const meta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (COLLECTION_BUCKETS[k] !== undefined && Array.isArray(v)) continue;
    meta[k] = v;
  }
  for (const [name, count] of Object.entries(COLLECTION_BUCKETS)) {
    const v = data[name];
    const items: unknown[] = Array.isArray(v) ? v : [];
    const buckets: unknown[][] = Array.from({ length: count }, () => []);
    for (const item of items) buckets[bucketOf(itemId(item), count)].push(item);
    for (let i = 0; i < count; i++) rows.set(bucketKey(name, i), buckets[i]);
  }
  rows.set(META_KEY, meta);
  return rows;
}

// Reassemble loadSnapshot()'s row set back into the serialized-store shape:
// spread the meta row, then concat each collection's buckets (bucket order
// doesn't matter — store.ts rebuilds Maps from the entries).
function assembleSnapshot(rows: { key: string; data: unknown }[]): unknown {
  const metaRow = rows.find((r) => r.key === META_KEY)?.data;
  const result: Record<string, unknown> =
    metaRow !== null && typeof metaRow === "object" && !Array.isArray(metaRow)
      ? { ...(metaRow as Record<string, unknown>) }
      : {};
  const collected = new Map<string, { idx: number; items: unknown[] }[]>();
  for (const row of rows) {
    if (row.key === META_KEY) continue;
    const sep = row.key.lastIndexOf(":");
    if (sep < 0) continue;
    const name = row.key.slice(0, sep);
    const idx = Number(row.key.slice(sep + 1));
    if (COLLECTION_BUCKETS[name] === undefined || !Number.isInteger(idx)) continue;
    if (!Array.isArray(row.data)) continue;
    const parts = collected.get(name) ?? [];
    parts.push({ idx, items: row.data });
    collected.set(name, parts);
  }
  for (const [name, parts] of collected) {
    // A collection stored in meta (non-array edge case) wins over its
    // always-written-empty buckets.
    if (name in result) continue;
    parts.sort((a, b) => a.idx - b.idx);
    result[name] = parts.flatMap((p) => p.items);
  }
  return result;
}

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
      // creates a fresh one that can re-resolve a recovered hostname. Drain
      // the old pool's sockets so abandoned clients don't leak.
      const old = pool;
      pool = null;
      ready = null;
      old?.end().catch(() => {});
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
        // vuln_snapshot is the LEGACY single-row format, kept so existing
        // deployments migrate on first load (and its last row stays behind
        // as a frozen emergency backup). vuln_store is the sharded format.
        `CREATE TABLE IF NOT EXISTS vuln_snapshot (
           id INT PRIMARY KEY,
           data JSONB NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
         );
         CREATE TABLE IF NOT EXISTS vuln_store (
           key TEXT PRIMARY KEY,
           data JSONB NOT NULL,
           updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
         );
         CREATE TABLE IF NOT EXISTS vuln_metrics_history (
           id BIGSERIAL PRIMARY KEY,
           ts TIMESTAMPTZ NOT NULL DEFAULT now(),
           company_id TEXT NULL,
           data JSONB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS vuln_metrics_history_company_ts_idx
           ON vuln_metrics_history (company_id, ts)`,
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
      p.query("SELECT MAX(updated_at) AS updated_at FROM vuln_store"),
      10000,
      "snapshotMeta",
    );
    const sharded = res.rows[0]?.updated_at ?? null;
    if (sharded) return { updatedAt: sharded };
    // No sharded rows yet — report the legacy snapshot's timestamp.
    const legacy = await withTimeout(
      p.query("SELECT updated_at FROM vuln_snapshot WHERE id = 1"),
      10000,
      "snapshotMeta(legacy)",
    );
    return { updatedAt: legacy.rows[0]?.updated_at ?? null };
  } catch {
    return { updatedAt: null };
  }
}

// Load the full snapshot. Prefers the sharded vuln_store rows; when that
// table is still empty (first boot after this format shipped) it falls back
// to the legacy single-row vuln_snapshot, and the next saveSnapshot writes
// the sharded format. The legacy row is intentionally left in place,
// untouched, as a frozen emergency backup of the pre-migration data.
// Errors propagate — store.ts's hydrate retry/fail-closed logic depends on
// loadSnapshot throwing rather than returning null on failure.
export async function loadSnapshot(): Promise<unknown | null> {
  const p = getPool();
  if (!p) return null;
  await withTimeout(ensureTable(), 10000, "ensureTable");
  const res = await withTimeout(
    p.query("SELECT key, data FROM vuln_store"),
    60000,
    "loadSnapshot",
  );
  if (res.rows.length > 0) {
    return assembleSnapshot(res.rows as { key: string; data: unknown }[]);
  }
  const legacy = await withTimeout(
    p.query("SELECT data FROM vuln_snapshot WHERE id = 1"),
    60000,
    "loadSnapshot(legacy)",
  );
  return legacy.rows[0]?.data ?? null;
}

const UPSERT_SQL = `INSERT INTO vuln_store (key, data, updated_at)
   VALUES ($1, $2, now())
   ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`;

// Persist the serialized store. Shards it into vuln_store rows, then UPSERTs
// only the rows whose content hash differs from what this process last
// committed — the common flush after a small mutation rewrites a handful of
// buckets instead of the whole ~100-300MB snapshot. All changed rows commit
// in one transaction so a reader (or a crash) never observes a half-written
// snapshot; the hash cache is only updated after COMMIT so a failed write is
// fully retried on the next flush. Callers (store.ts) already serialize
// saves through a single promise chain, so saves never overlap.
export async function saveSnapshot(data: unknown): Promise<void> {
  const p = getPool();
  if (!p) return;
  await withTimeout(ensureTable(), 10000, "ensureTable");

  // store.ts always passes serializeStore()'s plain object; tolerate anything
  // else by sharding an empty object with the value itself left to meta.
  const obj: Record<string, unknown> =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : { __raw: data };

  const rows = shardSnapshot(obj);
  const changed: { key: string; json: string; hash: string }[] = [];
  for (const [key, value] of rows) {
    const json = JSON.stringify(value);
    const hash = sha1Hex(json);
    if (lastWrittenHashes.get(key) !== hash) changed.push({ key, json, hash });
  }
  if (changed.length === 0) return;

  const client = await p.connect();
  try {
    // Same 60s budget the old whole-snapshot write had, now covering the
    // whole transaction (first post-boot save writes every row; steady state
    // writes a few).
    await withTimeout(
      (async () => {
        await client.query("BEGIN");
        for (const row of changed) {
          await client.query(UPSERT_SQL, [row.key, row.json]);
        }
        await client.query("COMMIT");
      })(),
      60000,
      "saveSnapshot",
    );
  } catch (err) {
    // Destroy the connection rather than returning it: after a timeout a
    // query may still be in flight, and closing the socket also aborts the
    // uncommitted transaction server-side. Hashes stay stale on purpose so
    // every changed row is retried by the next flush.
    client.release(err instanceof Error ? err : new Error(String(err)));
    throw err;
  }
  client.release();
  for (const row of changed) lastWrittenHashes.set(row.key, row.hash);
}

// --- metrics history ---------------------------------------------------------
// Append-only time series of metrics snapshots (per company plus a global row
// with company_id NULL), completely separate from the sharded store snapshot.
// Both functions are fail-safe: a DB outage logs and no-ops so trend capture
// never breaks a sync or a request.

export async function appendMetricsSnapshots(
  rows: { companyId: string | null; data: unknown }[],
): Promise<void> {
  const p = getPool();
  if (!p || rows.length === 0) return;
  try {
    await withTimeout(ensureTable(), 10000, "ensureTable");
    const client = await p.connect();
    try {
      await withTimeout(
        (async () => {
          await client.query("BEGIN");
          for (const row of rows) {
            await client.query(
              "INSERT INTO vuln_metrics_history (company_id, data) VALUES ($1, $2)",
              [row.companyId, JSON.stringify(row.data)],
            );
          }
          await client.query("COMMIT");
        })(),
        30000,
        "appendMetricsSnapshots",
      );
    } catch (err) {
      // Same as saveSnapshot: destroy the connection so an in-flight query
      // can't leak and the uncommitted transaction aborts server-side.
      client.release(err instanceof Error ? err : new Error(String(err)));
      throw err;
    }
    client.release();
  } catch (err) {
    console.error(
      "[persist] metrics snapshot append failed:",
      err instanceof Error ? err.message : err,
    );
  }
}

// Load history rows for one company (or the global series when companyId is
// null), newest `days` days, ordered oldest → newest.
export async function loadMetricsHistory(
  companyId: string | null,
  days: number,
): Promise<{ ts: string; data: unknown }[]> {
  const p = getPool();
  if (!p) return [];
  try {
    await withTimeout(ensureTable(), 10000, "ensureTable");
    const res = await withTimeout(
      p.query(
        `SELECT ts, data FROM vuln_metrics_history
         WHERE company_id IS NOT DISTINCT FROM $1
           AND ts >= now() - make_interval(days => $2::int)
         ORDER BY ts ASC`,
        [companyId, Math.max(1, Math.floor(days))],
      ),
      15000,
      "loadMetricsHistory",
    );
    return res.rows.map((r: { ts: unknown; data: unknown }) => ({
      ts: r.ts instanceof Date ? r.ts.toISOString() : String(r.ts),
      data: r.data,
    }));
  } catch (err) {
    console.error(
      "[persist] metrics history load failed:",
      err instanceof Error ? err.message : err,
    );
    return [];
  }
}
