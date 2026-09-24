import { Pool, type PoolClient } from "pg";
import { randomUUID, createHash } from "node:crypto";
import { applicationDatabase } from "./persist";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DEFAULT_COVERAGE, DashboardError, validateDisplayResult, parseDefinition,
  parseQueryInput, querySource, type QueryInput, type DashboardSource,
  type DashboardQuery, type ElasticDashboard, type QueryResult } from "./elastic-dashboard";
import { normalizeEndpoint, sealConnection, type ElasticConnection } from "./elastic-query-client";
import { DASHBOARD_CONNECTORS } from "./dashboard-query-connectors";
import { parseCrowdStrikeConnection, sealCrowdStrike, testCrowdStrikeConnection } from "./crowdstrike-dashboard-client";
import { type CrowdStrikeConnection } from "./crowdstrike-dashboard";

let dedicatedPool: Pool | undefined;
let ready: Promise<void> | undefined;
const runtime = globalThis as typeof globalThis & {
  __elasticDashboard?: { timer?: ReturnType<typeof setInterval>; ticking?: Promise<void>; running: number; previews: Map<string, number> };
};
const state: NonNullable<typeof runtime.__elasticDashboard> = runtime.__elasticDashboard ??= { running: 0, previews: new Map<string, number>() };

export async function dashboardDatabase(): Promise<Pool> {
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (url && !dedicatedPool) {
    dedicatedPool = new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000, statement_timeout: 5000 });
    dedicatedPool.on("error", () => {
      const old = dedicatedPool;
      dedicatedPool = undefined;
      ready = undefined;
      void old?.end().catch(() => {});
    });
  }
  const db = url ? dedicatedPool : applicationDatabase();
  if (!db) throw new DashboardError("Dashboard storage is not configured.", 503);
  if (!ready) {
    ready = (async () => {
      await db.query(`CREATE TABLE IF NOT EXISTS elastic_dashboard_connection (
        id INT PRIMARY KEY CHECK (id = 1), secret TEXT NOT NULL, revision INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS elastic_dashboard_queries (
        id TEXT PRIMARY KEY, definition JSONB NOT NULL, revision INT NOT NULL DEFAULT 1,
        result JSONB, refreshed_at TIMESTAMPTZ, attempted_at TIMESTAMPTZ,
        next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(), last_error TEXT
      );
      CREATE TABLE IF NOT EXISTS elastic_dashboard_audit (
        id BIGSERIAL PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
        query_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS elastic_dashboard_jobs (
        id UUID PRIMARY KEY, actor TEXT NOT NULL, kind TEXT NOT NULL,
        input JSONB NOT NULL, connection_revision INT NOT NULL, query_revision INT,
        status TEXT NOT NULL DEFAULT 'queued', result JSONB, error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), started_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '15 minutes'
      );
      ALTER TABLE elastic_dashboard_queries ADD COLUMN IF NOT EXISTS refresh_lease_until TIMESTAMPTZ;
      ALTER TABLE elastic_dashboard_queries ADD COLUMN IF NOT EXISTS refresh_requested BOOLEAN NOT NULL DEFAULT false;
      ALTER TABLE elastic_dashboard_queries ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
      CREATE TABLE IF NOT EXISTS dashboard_source_connections (
        source TEXT PRIMARY KEY, secret TEXT NOT NULL, revision INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE TABLE IF NOT EXISTS dashboard_daily_history (
        query_id TEXT NOT NULL, connection_revision INT NOT NULL, signature TEXT NOT NULL,
        day DATE NOT NULL, value BIGINT NOT NULL, observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (query_id, connection_revision, signature, day)
      )`);
      await db.query("INSERT INTO elastic_dashboard_queries (id, definition) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO NOTHING",
        [DEFAULT_COVERAGE.id, JSON.stringify(DEFAULT_COVERAGE)]);
    })().catch((error) => { ready = undefined; throw error; });
  }
  await ready;
  return db;
}

const database = dashboardDatabase;

export async function dashboardConnectionRevision(source: DashboardSource = "elastic"): Promise<number | null> {
  const db = await database();
  return (source === "elastic" ? await db.query("SELECT revision FROM elastic_dashboard_connection WHERE id = 1") :
    await db.query("SELECT revision FROM dashboard_source_connections WHERE source = $1", [source])).rows[0]?.revision ?? null;
}

async function connection(source: DashboardSource = "elastic"): Promise<{ value: unknown; revision: number; source: DashboardSource } | null> {
  const db = await database();
  const result = source === "elastic" ? await db.query("SELECT secret, revision FROM elastic_dashboard_connection WHERE id = 1") :
    await db.query("SELECT secret, revision FROM dashboard_source_connections WHERE source = $1", [source]);
  return result.rows.length ? { value: DASHBOARD_CONNECTORS[source].open(result.rows[0].secret), revision: result.rows[0].revision, source } : null;
}

function emptyQuery(): DashboardQuery {
  return { ...DEFAULT_COVERAGE, result: null, refreshedAt: null, attemptedAt: null, error: null };
}

export async function readDashboard(canManage: boolean): Promise<ElasticDashboard> {
  try {
    const db = await database();
    const saved = await connection().catch((error) => {
      // A rotated encryption secret requires reconnecting, not a disabled form.
      if (error instanceof DashboardError) return null;
      throw error;
    });
    const falcon = await connection("crowdstrike").catch((error) => {
      if (error instanceof DashboardError) return null;
      throw error;
    });
    const rows = await db.query("SELECT * FROM elastic_dashboard_queries WHERE deleted_at IS NULL ORDER BY id = 'asset-coverage' DESC, id");
    return {
      canManage, storageReady: true, connected: Boolean(saved),
      ...(canManage && saved ? { endpoint: (saved.value as ElasticConnection).endpoint } : {}),
      crowdstrike: { connected: Boolean(falcon), ...(canManage && falcon ? { region: (falcon.value as CrowdStrikeConnection).region } : {}) },
      queries: rows.rows.map((row) => ({ ...row.definition, result: row.result,
        refreshedAt: row.refreshed_at?.toISOString() ?? null,
        attemptedAt: row.attempted_at?.toISOString() ?? null, error: row.last_error })),
    };
  } catch {
    return { canManage, storageReady: false, connected: false, queries: [emptyQuery()] };
  }
}

async function limitedQuery(saved: unknown, query: string | QueryInput, async = true): Promise<QueryResult> {
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  const input = typeof query === "string" ? { query } : query;
  try { return await DASHBOARD_CONNECTORS[querySource(input)].execute(saved, input, async); } finally { state.running--; }
}

export function throttlePreview(actor: string): void {
  const last = state.previews.get(actor) ?? 0;
  if (Date.now() - last < 2000) throw new DashboardError("Wait two seconds between query previews.", 429);
  if (state.previews.size > 1000) state.previews.clear();
  state.previews.set(actor, Date.now());
}

export async function previewQuery(query: string | QueryInput, actor: string, queued = false, id?: string): Promise<QueryResult> {
  if (!queued) throttlePreview(actor);
  const input = parseQueryInput(typeof query === "string" ? { query } : query);
  const saved = await connection(querySource(input));
  if (!saved) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[querySource(input)].label} first.`, 409);
  const result = await limitedQuery(saved.value, input);
  return historyResult(await database(), input, id ?? "preview", saved.revision, result, false);
}

// The signature prevents edits to the population or measure from mixing history.
export function historySignature(input: QueryInput): string {
  return createHash("sha256").update(JSON.stringify({ source: querySource(input), query: input.query,
    dataset: input.crowdstrike?.dataset, measure: input.crowdstrike?.measure, group: input.crowdstrike?.groupBy })).digest("hex");
}

async function historyResult(db: Pool | PoolClient, input: QueryInput, id: string, revision: number, result: QueryResult, save: boolean): Promise<QueryResult> {
  if (querySource(input) !== "crowdstrike" || !input.crowdstrike?.history) return result;
  const signature = historySignature(input), today = new Date().toISOString().slice(0, 10), value = result.rows[0]?.[0];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || result.truncated) throw new DashboardError("Only a complete count can be recorded in history.");
  if (save) {
    await db.query(`INSERT INTO dashboard_daily_history (query_id, connection_revision, signature, day, value)
      VALUES ($1, $2, $3, $4::date, $5) ON CONFLICT (query_id, connection_revision, signature, day)
      DO UPDATE SET value = EXCLUDED.value, observed_at = now()`, [id, revision, signature, today, value]);
    await db.query("DELETE FROM dashboard_daily_history WHERE day < (now() AT TIME ZONE 'UTC')::date - 365");
  }
  const rows = await db.query(`SELECT to_char(day, 'YYYY-MM-DD') AS day, value::float8 AS value
    FROM dashboard_daily_history WHERE query_id = $1 AND connection_revision = $2 AND signature = $3
    AND day >= $4::date - 89 ORDER BY day`, [id, revision, signature, today]);
  const points = new Map<string, number>(rows.rows.map((row) => [row.day, row.value]));
  points.set(today, value);
  // Nulls make missed daily collections visible as gaps instead of zeros.
  const first = [...points.keys()].sort()[0];
  const values: QueryResult["rows"] = [];
  for (let day = Date.parse(`${first}T00:00:00Z`); day <= Date.parse(`${today}T00:00:00Z`); day += 86400000) {
    const label = new Date(day).toISOString();
    values.push([label, points.get(label.slice(0, 10)) ?? null]);
  }
  return { columns: [{ name: "day", type: "date" }, { name: input.crowdstrike.measure, type: "long" }], rows: values, truncated: false,
    note: "Last successful observation per UTC day, up to 90 days. Missing collections are gaps. History begins with the first saved collection; preview does not save history." };
}

export async function saveConnection(value: unknown, actor: string): Promise<void> {
  if (!value || typeof value !== "object") throw new DashboardError("Enter connection details.");
  const body = value as Record<string, unknown>;
  const endpoint = normalizeEndpoint(body.endpoint);
  const supplied = typeof body.apiKey === "string" ? body.apiKey.trim() : "";
  // An explicitly supplied key also recovers a connection encrypted with an old
  // session secret. Only decrypt the old connection when reusing its key.
  const previous = supplied ? null : await connection();
  // Never forward an existing key to a newly entered endpoint.
  const old = previous?.value as ElasticConnection | undefined;
  const apiKey = supplied || (old?.endpoint === endpoint ? old.apiKey : "");
  if (!apiKey || apiKey.length > 8192 || /\s/.test(apiKey)) throw new DashboardError("Enter the encoded API key for this endpoint.");
  const candidate = { endpoint, apiKey };
  throttlePreview(actor);
  // Verify the actual first query, including required index access, before saving.
  await limitedQuery(candidate, DEFAULT_COVERAGE.query, false);
  const sealed = sealConnection(candidate);
  const db = await database();
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    await client.query(`INSERT INTO elastic_dashboard_connection (id, secret) VALUES (1, $1)
      ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret,
      revision = elastic_dashboard_connection.revision + 1, updated_at = now()`, [sealed]);
    // Old-source results must never be presented as results from the new connection.
    await client.query("UPDATE elastic_dashboard_queries SET result = NULL, refreshed_at = NULL, attempted_at = NULL, last_error = NULL, refresh_lease_until = NULL, next_attempt = now() WHERE COALESCE(definition->>'source', 'elastic') = 'elastic'");
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action) VALUES ($1, 'connection.updated')", [actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh();
}

export async function saveCrowdStrikeConnection(value: unknown, actor: string): Promise<void> {
  // Require explicit credentials on every replacement; never forward saved
  // secrets to a different cloud or copy the unrelated scanner credentials.
  const candidate = parseCrowdStrikeConnection(value);
  throttlePreview(actor);
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  try { await testCrowdStrikeConnection(candidate); } finally { state.running--; }
  const secret = sealCrowdStrike(candidate), db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    await client.query(`INSERT INTO dashboard_source_connections (source, secret) VALUES ('crowdstrike', $1)
      ON CONFLICT (source) DO UPDATE SET secret = EXCLUDED.secret, revision = dashboard_source_connections.revision + 1, updated_at = now()`, [secret]);
    await client.query(`UPDATE elastic_dashboard_queries SET result = NULL, refreshed_at = NULL, attempted_at = NULL,
      last_error = NULL, refresh_lease_until = NULL, next_attempt = now() WHERE definition->>'source' = 'crowdstrike'`);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action) VALUES ($1, 'crowdstrike.connection.updated')", [actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh();
}

// Save settings first. Remote validation and execution belong to the refresh
// worker, so adding a tile never waits for Elastic/CrowdStrike or the job queue.
export async function addDashboardTile(value: unknown, actor: string): Promise<{ saved: true; query: DashboardQuery }> {
  const body = value as Record<string, unknown>;
  const id = typeof body?.id === "string" ? body.id : randomUUID();
  const definition = parseDefinition(body, id), source = querySource(definition);
  const db = await database(), client = await db.connect();
  let tile: DashboardQuery;
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const connected = source === "elastic" ? await client.query("SELECT id FROM elastic_dashboard_connection WHERE id = 1") :
      await client.query("SELECT source FROM dashboard_source_connections WHERE source = $1", [source]);
    if (!connected.rowCount) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[source].label} first.`, 409);
    const previous = (await client.query("SELECT definition, result, refreshed_at, deleted_at FROM elastic_dashboard_queries WHERE id = $1", [id])).rows[0];
    if (previous?.deleted_at) throw new DashboardError("This tile was deleted. Add a new tile instead.", 409);
    const count = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_queries WHERE id <> $1 AND deleted_at IS NULL", [id]);
    if (count.rows[0].count >= 24) throw new DashboardError("This dashboard supports up to 24 saved queries.");
    let result: QueryResult | null = null, refreshedAt: string | null = null;
    if (previous?.result && JSON.stringify(parseQueryInput(previous.definition)) === JSON.stringify(parseQueryInput(definition))) {
      try { validateDisplayResult(previous.result, definition); result = previous.result; refreshedAt = previous.refreshed_at?.toISOString() ?? null; }
      catch { /* A new display can wait for its first valid result. */ }
    }
    await client.query(`INSERT INTO elastic_dashboard_queries
      (id, definition, result, refreshed_at, next_attempt, refresh_requested)
      VALUES ($1, $2::jsonb, $3::jsonb, $4::timestamptz, now(), true)
      ON CONFLICT (id) DO UPDATE SET definition = EXCLUDED.definition, result = EXCLUDED.result,
      refreshed_at = EXCLUDED.refreshed_at, revision = elastic_dashboard_queries.revision + 1,
      attempted_at = NULL, last_error = NULL, next_attempt = now(), refresh_lease_until = NULL, refresh_requested = true`,
      [id, JSON.stringify(definition), result ? JSON.stringify(result) : null, refreshedAt]);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action, query_id) VALUES ($1, 'query.saved', $2)", [actor, id]);
    await client.query("COMMIT");
    tile = { ...definition, result, refreshedAt, attemptedAt: null, error: null };
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh();
  return { saved: true, query: tile };
}

export async function deleteDashboardTile(id: string, actor: string): Promise<void> {
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(id)) throw new DashboardError("Invalid tile ID.");
  const db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    // Keep a tombstone so stale forms/jobs and the default seed cannot recreate it.
    const removed = await client.query(`UPDATE elastic_dashboard_queries SET deleted_at = now(),
      revision = revision + 1, refresh_requested = false, refresh_lease_until = NULL,
      result = NULL, refreshed_at = NULL, last_error = NULL WHERE id = $1 AND deleted_at IS NULL RETURNING id`, [id]);
    if (removed.rowCount) {
      await client.query("DELETE FROM dashboard_daily_history WHERE query_id = $1", [id]);
      await client.query(`UPDATE elastic_dashboard_jobs SET status = 'failed', result = NULL,
        error = 'This tile was deleted.' WHERE input->>'id' = $1`, [id]);
      await client.query("INSERT INTO elastic_dashboard_audit (actor, action, query_id) VALUES ($1, 'query.deleted', $2)", [actor, id]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

export async function saveQuery(value: unknown, actor: string, job?: { id: string; connectionRevision: number; queryRevision: number | null }): Promise<void> {
  const body = value as Record<string, unknown>;
  const id = typeof body?.id === "string" ? body.id : randomUUID();
  const definition = parseDefinition(body, id);
  const source = querySource(definition), saved = await connection(source);
  if (!saved) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[source].label} first.`, 409);
  if (!job) throttlePreview(actor);
  const rawResult = await limitedQuery(saved.value, definition);
  const db = await database();
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const current = source === "elastic" ? await client.query("SELECT revision FROM elastic_dashboard_connection WHERE id = 1") :
      await client.query("SELECT revision FROM dashboard_source_connections WHERE source = $1", [source]);
    if (current.rows[0]?.revision !== saved.revision) throw new DashboardError("The connection changed. Preview and save again.", 409);
    const existing = (await client.query("SELECT deleted_at FROM elastic_dashboard_queries WHERE id = $1", [id])).rows[0];
    if (existing?.deleted_at) throw new DashboardError("This tile was deleted. Add a new tile instead.", 409);
    if (job) {
      const activeJob = await client.query("SELECT id FROM elastic_dashboard_jobs WHERE id = $1 AND status = 'running' AND started_at > now() - interval '7 minutes'", [job.id]);
      const query = await client.query("SELECT revision FROM elastic_dashboard_queries WHERE id = $1", [id]);
      if (!activeJob.rowCount || job.connectionRevision !== saved.revision || (query.rows[0]?.revision ?? null) !== job.queryRevision) {
        throw new DashboardError("The query or connection changed while this save was running. Reload and save again.", 409);
      }
    }
    const count = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_queries WHERE id <> $1 AND deleted_at IS NULL", [id]);
    if (count.rows[0].count >= 24) throw new DashboardError("This dashboard supports up to 24 saved queries.");
    const result = await historyResult(client, definition, id, saved.revision, rawResult, true);
    validateDisplayResult(result, definition);
    await client.query(`INSERT INTO elastic_dashboard_queries (id, definition, result, refreshed_at, attempted_at, next_attempt)
      VALUES ($1, $2::jsonb, $3::jsonb, now(), now(), now() + $4 * interval '1 minute')
      ON CONFLICT (id) DO UPDATE SET definition = EXCLUDED.definition, result = EXCLUDED.result,
      revision = elastic_dashboard_queries.revision + 1, refreshed_at = now(), attempted_at = now(),
      next_attempt = EXCLUDED.next_attempt, last_error = NULL, refresh_lease_until = NULL`,
      [id, JSON.stringify(definition), JSON.stringify(result), definition.refreshMinutes]);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action, query_id) VALUES ($1, 'query.saved', $2)", [actor, id]);
    if (job) await client.query("UPDATE elastic_dashboard_jobs SET status = 'succeeded', result = '{\"saved\":true}'::jsonb WHERE id = $1", [job.id]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

async function refreshQueries(force = false): Promise<void> {
  if (!elasticVulnEnabled()) return;
  const db = await database();
  const due = await db.query(`SELECT id, definition, revision FROM elastic_dashboard_queries
    WHERE deleted_at IS NULL AND ((definition->>'enabled')::boolean = true OR refresh_requested = true OR $1)
    AND (refresh_lease_until IS NULL OR refresh_lease_until <= now())
    AND (next_attempt <= now() OR ($1 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds')))
    ORDER BY next_attempt LIMIT 24`, [force]);
  for (const row of due.rows) {
    // Leave pending tiles due while previews occupy the execution slots.
    if (state.running >= 2) break;
    const definition = parseDefinition(row.definition, row.id);
    let saved;
    try { saved = await connection(querySource(definition)); }
    catch (error) {
      if (!(error instanceof DashboardError)) throw error;
      await db.query(`UPDATE elastic_dashboard_queries SET last_error = $3, attempted_at = now(), refresh_requested = false,
        next_attempt = now() + $4 * interval '1 minute' WHERE id = $1 AND revision = $2`,
        [row.id, row.revision, error.message, definition.refreshMinutes]);
      continue;
    }
    if (!saved) continue;
    if (state.running >= 2) break;
    // Atomic claim across app instances. A refresh never erases the last success.
    const claim = await db.query(`UPDATE elastic_dashboard_queries SET attempted_at = now(), refresh_requested = false,
      next_attempt = now() + $3 * interval '1 minute', refresh_lease_until = now() + interval '7 minutes'
      WHERE id = $1 AND revision = $2 AND (refresh_lease_until IS NULL OR refresh_lease_until <= now()) AND (next_attempt <= now() OR
      ($4 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds'))) RETURNING id`,
      [row.id, row.revision, definition.refreshMinutes, force]);
    if (!claim.rowCount) continue;
    let result: QueryResult | null = null;
    let error: string | null = null;
    try {
      result = await limitedQuery(saved.value, definition);
    } catch (err) {
      if (err instanceof DashboardError && err.status === 429 && state.running >= 2) {
        await db.query(`UPDATE elastic_dashboard_queries SET refresh_requested = true,
          refresh_lease_until = NULL, next_attempt = now() WHERE id = $1 AND revision = $2`, [row.id, row.revision]);
        break;
      }
      result = null;
      error = err instanceof DashboardError ? err.message : "Query refresh failed. Check the connection and query, then retry.";
    }
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(804201)");
      const current = saved.source === "elastic" ? await client.query("SELECT revision FROM elastic_dashboard_connection WHERE id = 1") :
        await client.query("SELECT revision FROM dashboard_source_connections WHERE source = $1", [saved.source]);
      const latest = await client.query("SELECT revision FROM elastic_dashboard_queries WHERE id = $1", [row.id]);
      if (current.rows[0]?.revision !== saved.revision || latest.rows[0]?.revision !== row.revision) { await client.query("ROLLBACK"); continue; }
      if (result) {
        // Validate before writing history; a schema mismatch preserves the cache.
        const candidate = await historyResult(client, definition, row.id, saved.revision, result, false);
        try { validateDisplayResult(candidate, definition); }
        catch (err) { result = null; error = err instanceof DashboardError ? err.message : "Invalid chart result."; }
        if (result) result = await historyResult(client, definition, row.id, saved.revision, result, true);
      }
      await client.query(`UPDATE elastic_dashboard_queries SET
      result = CASE WHEN $3::jsonb IS NULL THEN result ELSE $3::jsonb END,
      refreshed_at = CASE WHEN $3::jsonb IS NULL THEN refreshed_at ELSE now() END,
      last_error = $4, refresh_lease_until = NULL, next_attempt = now() + $5 * interval '1 minute'
      WHERE id = $1 AND revision = $2`,
      [row.id, row.revision, result ? JSON.stringify(result) : null, error, definition.refreshMinutes]);
      await client.query("COMMIT");
    } catch (err) { await client.query("ROLLBACK"); throw err; } finally { client.release(); }
  }
}

export function triggerRefresh(force = false): void {
  if (state.ticking) return;
  state.ticking = refreshQueries(force).catch(() => {
    // No credentials, query text, or result content in process logs.
    console.error("[elastic-dashboard] Refresh could not complete.");
  }).finally(() => { state.ticking = undefined; });
}

export function startElasticDashboardScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  state.timer = setInterval(() => triggerRefresh(), 60_000);
  state.timer.unref();
  triggerRefresh();
}
