import { Pool, type PoolClient } from "pg";
import { createHash } from "node:crypto";
import { createReportingInputDigests, publishReportingInputRevisions, publishSqlReportingChanges, reportingSnapshotManifest } from "./db/customer-reporting-revisions.mjs";
import { readPlatformAuthority, bindPlatformWriter } from "./db/platform-authority.mjs";
import { loadPlatformStore, preparePlatformStore, commitPreparedPlatformStore, savePlatformDelta, platformSaveTimeoutMs } from "./db/platform-store.mjs";
import { loadCommittedPlatform } from "./db/platform-reader.mjs";

// Snapshot persistence. The in-memory store (companies, folders, scans,
// findings, assets, settings, counter) is serialized by store.ts and flushed
// here on a debounced timer. Storage is SHARDED across many rows in
// vuln_store (key TEXT PRIMARY KEY, data JSONB): each collection is split
// into a fixed number of hash buckets so no single JSONB value grows without
// bound (Postgres caps a jsonb value at ~255MB and the findings set alone is
// heading there), and unchanged buckets are skipped on every flush via a
// per-key content hash, so steady-state writes touch only the rows that
// actually changed. The compatibility path keeps that format. After explicit
// SQL cutover, row tables are authoritative and this module hydrates their RAM
// compatibility cache. A database epoch/revision fence prevents stale writers.

// Next may bundle this module separately for instrumentation and API routes.
// The RAM store is process-global, so its pool and committed writer generation
// must have the same lifetime. Module-local state loses the loaded SQL token
// when another route tries to save, or uses an obsolete legacy hash cache.
type PersistenceRuntime = {
  pool: Pool | null; ready: Promise<void> | null; target?: string;
  lastWrittenHashes: Map<string, string>; lastReportingManifest: string | null;
  reportingDigestCache: Map<string, any>;
  platformAuthority: Awaited<ReturnType<typeof readPlatformAuthority>>;
  platformState: Awaited<ReturnType<typeof loadPlatformStore>>["state"] | null;
};
const persistenceGlobal = globalThis as typeof globalThis & { __vulnDatabasePersistenceV1?: PersistenceRuntime };
const persistence: PersistenceRuntime = persistenceGlobal.__vulnDatabasePersistenceV1 ??= {
  pool: null, ready: null, lastWrittenHashes: new Map(), lastReportingManifest: null,
  reportingDigestCache: new Map(), platformAuthority: null, platformState: null,
};
const lastWrittenHashes = persistence.lastWrittenHashes;
const reportingDigestCache = persistence.reportingDigestCache;
export function strictPlatformPersistence(): boolean {
  return process.env.VULN_PLATFORM_STORE === "sql" || persistence.platformAuthority?.mode === "sql";
}

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
async function shardSnapshot(data: Record<string, unknown>): Promise<Map<string, unknown>> {
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
    let processed = 0;
    for (const item of items) {
      buckets[bucketOf(itemId(item), count)].push(item);
      // Large Defender generations contain hundreds of thousands of findings.
      // Let requests run between bounded batches of synchronous hashing work.
      if (++processed % 2000 === 0) await new Promise<void>(resolve => setImmediate(resolve));
    }
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
  if (persistence.target && persistence.target !== process.env.DATABASE_URL) throw new Error("Database target changed; restart before using platform storage.");
  persistence.target = process.env.DATABASE_URL;
  if (!persistence.pool) {
    persistence.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      // The DigitalOcean managed Postgres cluster backing this allows 397
      // concurrent backend connections; this single Node process was
      // needlessly capped at 3, which meant concurrent Spotlight discovery
      // partitions (each holding a client open for the duration of its own
      // transaction) were competing with every other concurrent DB use in
      // the app -- ticket reconciliation, the risk-refresh scheduler,
      // ordinary page loads -- for a shared pool of only 3. 20 stays
      // trivially far under the cluster ceiling (this database is also
      // shared with other apps on the same cluster) while giving real
      // headroom for several concurrent discovery partitions plus
      // everything else the app does at the same time.
      max: process.env.VULN_RUNTIME_ROLE === "web" ? 6 : 20,
      ...(process.env.VULN_RUNTIME_ROLE === "web" ? { options: "-c default_transaction_read_only=on", query_timeout: 35000 } : {}),
      // Fail fast if the DB is unreachable so hydration can fall back to
      // in-memory instead of hanging every request. 8s was too tight under
      // the Spotlight sync's sustained concurrent DB load (a worker-lock
      // connection held for the whole multi-hour run, plus fanned-out
      // discovery/hydration calls): a brief stall opening a *new* physical
      // connection to the shared DigitalOcean cluster was enough to blow
      // this and abort an otherwise-resumable run with pg-pool's
      // "Connection terminated due to connection timeout".
      connectionTimeoutMillis: 15000,
      idleTimeoutMillis: 30000,
    });
    const activePool = persistence.pool;
    activePool.on("error", (err) => {
      console.error("[persist] pool error:", err.message);
      // Reset the cached pool on fatal errors so the next getPool() call
      // creates a fresh one that can re-resolve a recovered hostname. Drain
      // the old pool's sockets so abandoned clients don't leak.
      const old = activePool;
      if (persistence.pool === activePool) { persistence.pool = null; persistence.ready = null; }
      old?.end().catch(() => {});
    });
  }
  return persistence.pool;
}

// Reject if the DB op doesn't finish in time, so a slow/unreachable DB never
// blocks a request indefinitely.
async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function ensureTable(): Promise<void> {
  if (process.env.VULN_RUNTIME_ROLE === "web") return;
  const p = getPool();
  if (!p) return;
  if (!persistence.ready) {
    persistence.ready = p
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
        persistence.ready = null;
        throw err;
      });
  }
  return persistence.ready;
}

export function persistenceEnabled(): boolean {
  return Boolean(process.env.DATABASE_URL);
}

// Independent modules may use the established pool for their own tables.
// They must not modify the scanner snapshot tables or persistence bookkeeping.
export function applicationDatabase(): Pool | null {
  return getPool();
}

// Reader bookkeeping never touches the writer's epoch/index/dirty state.
export async function loadCommittedRead(previous?: Awaited<ReturnType<typeof loadCommittedPlatform>>) {
  if (process.env.VULN_PLATFORM_STORE !== "sql") throw new Error("The committed reader requires SQL platform storage.");
  const pool = getPool();
  if (!pool) throw new Error("Platform database is not configured.");
  const client = await pool.connect();
  let failed: Error | undefined;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout = '30s'");
    const snapshot = await loadCommittedPlatform(client, previous);
    await client.query("COMMIT");
    return snapshot;
  } catch (error) {
    failed = error instanceof Error ? error : new Error(String(error));
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally { client.release(failed); }
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
    if ((await readPlatformAuthority(p))?.mode === "sql") {
      const row = (await p.query("SELECT updated_at FROM app_store_authority WHERE id=1")).rows[0];
      return { updatedAt: row?.updated_at ?? null };
    }
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
  // Fetch shard keys first, then each row individually: one giant
  // SELECT * of a multi-hundred-MB table can outlast any single-query
  // timeout and buffers everything at once, wedging the event loop. Per-row
  // reads keep each query small and yield between rows so the server keeps
  // answering requests while hydration streams in.
  const client = await p.connect();
  let releaseError: Error | undefined;
  try {
    // Pin one committed generation across all shard reads. Without this a
    // concurrent save could pair old findings with a new publication marker.
    await withTimeout(client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"),10000,"loadSnapshot(begin)");
    persistence.platformAuthority = await readPlatformAuthority(client);
    if (persistence.platformAuthority?.mode === "sql") {
      if (process.env.VULN_PLATFORM_STORE !== "sql") throw new Error("SQL authority requires VULN_PLATFORM_STORE=sql; refusing the frozen legacy snapshot.");
      const loaded = await loadPlatformStore(client, persistence.platformAuthority);
      await client.query("COMMIT");
      persistence.platformState = loaded.state;
      lastWrittenHashes.clear(); reportingDigestCache.clear();
      return loaded.data;
    }
    if (process.env.VULN_PLATFORM_STORE === "sql") throw new Error("SQL authority has not been activated; run the reviewed maintenance transition first.");
    const keysRes = await withTimeout(
      client.query("SELECT key FROM vuln_store"),
      15000,
      "loadSnapshot(keys)",
    );
    if (keysRes.rows.length > 0) {
      const rows: { key: string; data: unknown }[] = [];
      for (const { key } of keysRes.rows as { key: string }[]) {
        const row = await withTimeout(
          client.query("SELECT data FROM vuln_store WHERE key = $1", [key]),
          30000,
          `loadSnapshot(${key})`,
        );
        if (row.rows[0]) rows.push({ key, data: row.rows[0].data });
        // Yield so concurrent requests aren't starved during a large load.
        await new Promise((resolve) => setImmediate(resolve));
      }
      const reportingManifest = process.env.VULN_REPORTING_INPUT_REVISIONS === "true" ? await reportingSnapshotManifest(client) : null;
      await withTimeout(client.query("COMMIT"),10000,"loadSnapshot(commit)");
      persistence.lastReportingManifest = reportingManifest?.hash ?? null;
      // A restart should not rewrite every unchanged shard. Prime from the
      // committed snapshot; subsequent mutations still compare content hashes.
      lastWrittenHashes.clear();
      for (const row of rows) {
        lastWrittenHashes.set(row.key,sha1Hex(JSON.stringify(row.data)));
        await new Promise<void>(resolve => setImmediate(resolve));
      }
      return assembleSnapshot(rows);
    }
    const legacy = await withTimeout(
      client.query("SELECT data FROM vuln_snapshot WHERE id = 1"),
      120000,
      "loadSnapshot(legacy)",
    );
    await withTimeout(client.query("COMMIT"),10000,"loadSnapshot(commit)");
    lastWrittenHashes.clear();
    persistence.lastReportingManifest = null;
    return legacy.rows[0]?.data ?? null;
  } catch (error) {
    releaseError = error instanceof Error ? error : new Error(String(error));
    throw error;
  } finally {
    client.release(releaseError);
  }
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
export async function saveSnapshot(data: unknown, options?: { guard?: () => void; changes?: Record<string, string[]> }): Promise<void> {
  if (process.env.VULN_RUNTIME_ROLE === "web") throw new Error("The web reader cannot save platform data.");
  const p = getPool();
  if (!p) return;
  await withTimeout(ensureTable(), 10000, "ensureTable");

  // store.ts always passes serializeStore()'s plain object; tolerate anything
  // else by sharding an empty object with the value itself left to meta.
  const obj: Record<string, unknown> =
    data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : { __raw: data };

  if (strictPlatformPersistence()) {
    if (!persistence.platformState || persistence.platformAuthority?.mode !== "sql") throw new Error("A committed SQL generation must be loaded before writing.");
    // Full comparisons/report hashing can exceed PostgreSQL's idle transaction
    // limit. Prepare BEFORE borrowing a connection or locking the authority row.
    const reporting = createReportingInputDigests(reportingDigestCache);
    const startedAt = Date.now();
    let deadline = startedAt + 300000, cancelled = false, phase = "prepare";
    let client: PoolClient | undefined;
    const guard = () => {
      if (cancelled || Date.now() >= deadline) throw new Error(`SQL platform ${phase} deadline exceeded.`);
      options?.guard?.();
    };
    try {
      const prepared = options?.changes === undefined
        ? await preparePlatformStore(obj, persistence.platformState, { reporting, guard }) : undefined;
      const digests = prepared ? reporting.finish() : undefined;
      guard();
      const preparedMs = Date.now() - startedAt;
      const timeoutMs = platformSaveTimeoutMs(options?.changes, prepared?.findingChanges);
      phase = "connect";
      client = await p.connect();
      guard();
      const activeClient = client;
      deadline = Date.now() + timeoutMs;
      if (timeoutMs > 300000) console.info(`[persist] Large SQL publication started: ${options?.changes?.findings?.length ?? prepared?.findingChanges} findings; ${timeoutMs / 1000}s limit.`);
      const next = await withTimeout((async () => {
        phase = "write";
        await activeClient.query("BEGIN; SET LOCAL statement_timeout='60s'; SET LOCAL lock_timeout='10s'; SET LOCAL idle_in_transaction_session_timeout='90s'");
        const next = prepared
          ? await commitPreparedPlatformStore(activeClient, prepared, { guard })
          : await savePlatformDelta(activeClient, obj, persistence.platformState, options!.changes!, { guard });
        phase = "reporting";
        if ("changedKeys" in next) await publishSqlReportingChanges(activeClient, next.changedKeys);
        else await publishReportingInputRevisions(activeClient, digests!);
        guard();
        phase = "commit";
        await activeClient.query("COMMIT");
        return next;
      })(), timeoutMs, "SQL platform save");
      persistence.platformState = next; persistence.platformAuthority = next.authority;
      if ("changedKeys" in next) reportingDigestCache.clear();
      else reporting.committed();
      console.info(`[persist] SQL save committed: scope=${prepared ? "full" : "delta"} prepareMs=${preparedMs} totalMs=${Date.now() - startedAt} inserted=${next.counts.inserted} updated=${next.counts.updated} deleted=${next.counts.deleted} metadata=${next.counts.metadata}.`);
    } catch (error) {
      cancelled = true;
      console.error(`[persist] SQL save stopped: phase=${phase} scope=${options?.changes === undefined ? "full" : "delta"} elapsedMs=${Date.now() - startedAt} code=${(error as {code?: string})?.code ?? "none"}.`);
      client?.release(error instanceof Error ? error : new Error(String(error)));
      throw error;
    }
    client?.release();
    return;
  }

  const rows = await shardSnapshot(obj);
  const reporting = process.env.VULN_REPORTING_INPUT_REVISIONS === "true" ? createReportingInputDigests(reportingDigestCache) : null;
  const changed: { key: string; json: string; hash: string }[] = [];
  for (const [key, value] of rows) {
    const json = JSON.stringify(value);
    const hash = sha1Hex(json);
    await reporting?.bucket(key, json, hash);
    if (lastWrittenHashes.get(key) !== hash) changed.push({ key, json, hash });
    await new Promise<void>(resolve => setImmediate(resolve));
  }
  if (changed.length === 0 && !reporting) return;
  const reportingDigests = reporting?.finish();

  const client = await p.connect();
  let committedReportingManifest: string | null = null;
  let committedAuthority = persistence.platformAuthority;
  try {
    // Bound each statement/lock wait, but allow a large atomic publication to
    // take longer than the old 60-second budget for ALL shards combined.
    await withTimeout(
      (async () => {
        await client.query("BEGIN");
        await client.query("SET LOCAL statement_timeout = '60s'");
        await client.query("SET LOCAL lock_timeout = '10s'");
        await bindPlatformWriter(client, persistence.platformAuthority);
        if (reportingDigests) {
          // Detect another/older writer rather than certify its data using this
          // process's stale hash cache. Readers remain free to use MVCC snapshots.
          await client.query("LOCK TABLE public.vuln_store IN SHARE ROW EXCLUSIVE MODE");
          const present = (await client.query("SELECT 1 FROM public.vuln_store LIMIT 1")).rowCount;
          if (present && (!persistence.lastReportingManifest || (await reportingSnapshotManifest(client)).hash !== persistence.lastReportingManifest))
            throw new Error("Platform snapshot changed outside this writer; reload before publishing report revisions.");
        }
        for (const row of changed) {
          await client.query(UPSERT_SQL, [row.key, row.json]);
        }
        if (persistence.platformAuthority && changed.length) committedAuthority = (await client.query("UPDATE app_store_authority SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1 RETURNING mode,enforced,epoch::text,revision::text")).rows[0];
        if (reportingDigests) committedReportingManifest = await publishReportingInputRevisions(client, reportingDigests);
        await client.query("COMMIT");
      })(),
      300000,
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
  persistence.platformAuthority = committedAuthority;
  persistence.lastReportingManifest = committedReportingManifest;
  reporting?.committed();
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

// Historical snapshots retain their original customer_id and are shown as a
// separate series after the approved consolidation. Composite measures such
// as MTTR must never be added to the canonical series.
export async function loadLegacyCustomerMetricsHistory(
  companyId: string,
): Promise<{ ts: string; sourceCompanyId: string; sourceCompanyName: string; data: unknown }[]> {
  const source = companyId === "CO-229336"
    ? { id: "CO-9150", name: "GMI Scans" }
    : companyId === "CO-229438"
      ? { id: "CO-9153", name: "Valor Global Scans" }
      : null;
  if (!source) return [];
  const p = getPool();
  if (!p) return [];
  try {
    await withTimeout(ensureTable(), 10000, "ensureTable");
    const res = await withTimeout(p.query(
      `SELECT ts, data FROM vuln_metrics_history
       WHERE company_id=$1
       ORDER BY ts ASC`,
      [source.id],
    ), 15000, "loadLegacyCustomerMetricsHistory");
    return res.rows.map((r: { ts: unknown; data: unknown }) => ({
      ts: r.ts instanceof Date ? r.ts.toISOString() : String(r.ts),
      sourceCompanyId: source.id,
      sourceCompanyName: source.name,
      data: r.data,
    }));
  } catch (err) {
    console.error("[persist] legacy metrics history load failed:", err instanceof Error ? err.message : err);
    return [];
  }
}
