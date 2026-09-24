import { Pool } from "pg";
import { randomUUID } from "node:crypto";
import { applicationDatabase } from "./persist";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DEFAULT_COVERAGE, DashboardError, validateDisplayResult, parseDefinition,
  type DashboardQuery, type ElasticDashboard, type QueryResult } from "./elastic-dashboard";
import { executeEsql, normalizeEndpoint, openConnection, sealConnection, type ElasticConnection } from "./elastic-query-client";

let dedicatedPool: Pool | undefined;
let ready: Promise<void> | undefined;
const runtime = globalThis as typeof globalThis & {
  __elasticDashboard?: { timer?: ReturnType<typeof setInterval>; ticking?: Promise<void>; running: number; previews: Map<string, number> };
};
const state: NonNullable<typeof runtime.__elasticDashboard> = runtime.__elasticDashboard ??= { running: 0, previews: new Map<string, number>() };

async function database(): Promise<Pool> {
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
      )`);
      await db.query("INSERT INTO elastic_dashboard_queries (id, definition) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO NOTHING",
        [DEFAULT_COVERAGE.id, JSON.stringify(DEFAULT_COVERAGE)]);
    })().catch((error) => { ready = undefined; throw error; });
  }
  await ready;
  return db;
}

async function connection(): Promise<{ value: ElasticConnection; revision: number } | null> {
  const db = await database();
  const result = await db.query("SELECT secret, revision FROM elastic_dashboard_connection WHERE id = 1");
  return result.rows.length ? { value: openConnection(result.rows[0].secret), revision: result.rows[0].revision } : null;
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
    const rows = await db.query("SELECT * FROM elastic_dashboard_queries ORDER BY id = 'asset-coverage' DESC, id");
    return {
      canManage, storageReady: true, connected: Boolean(saved),
      ...(canManage && saved ? { endpoint: saved.value.endpoint } : {}),
      queries: rows.rows.map((row) => ({ ...row.definition, result: row.result,
        refreshedAt: row.refreshed_at?.toISOString() ?? null,
        attemptedAt: row.attempted_at?.toISOString() ?? null, error: row.last_error })),
    };
  } catch {
    return { canManage, storageReady: false, connected: false, queries: [emptyQuery()] };
  }
}

async function limitedQuery(saved: ElasticConnection, query: string): Promise<QueryResult> {
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  try { return await executeEsql(saved, query); } finally { state.running--; }
}

export function throttlePreview(actor: string): void {
  const last = state.previews.get(actor) ?? 0;
  if (Date.now() - last < 2000) throw new DashboardError("Wait two seconds between query previews.", 429);
  if (state.previews.size > 1000) state.previews.clear();
  state.previews.set(actor, Date.now());
}

export async function previewQuery(query: string, actor: string): Promise<QueryResult> {
  throttlePreview(actor);
  const saved = await connection();
  if (!saved) throw new DashboardError("Connect Elasticsearch first.", 409);
  return limitedQuery(saved.value, query);
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
  const apiKey = supplied || (previous?.value.endpoint === endpoint ? previous.value.apiKey : "");
  if (!apiKey || apiKey.length > 8192 || /\s/.test(apiKey)) throw new DashboardError("Enter the encoded API key for this endpoint.");
  const candidate = { endpoint, apiKey };
  throttlePreview(actor);
  // Verify the actual first query, including required index access, before saving.
  await limitedQuery(candidate, DEFAULT_COVERAGE.query);
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
    await client.query("UPDATE elastic_dashboard_queries SET result = NULL, refreshed_at = NULL, attempted_at = NULL, last_error = NULL, next_attempt = now()");
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action) VALUES ($1, 'connection.updated')", [actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh();
}

export async function saveQuery(value: unknown, actor: string): Promise<void> {
  const body = value as Record<string, unknown>;
  const id = typeof body?.id === "string" ? body.id : randomUUID();
  const definition = parseDefinition(body, id);
  const saved = await connection();
  if (!saved) throw new DashboardError("Connect Elasticsearch first.", 409);
  throttlePreview(actor);
  const result = await limitedQuery(saved.value, definition.query);
  validateDisplayResult(result, definition);
  const db = await database();
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const current = await client.query("SELECT revision FROM elastic_dashboard_connection WHERE id = 1");
    if (current.rows[0]?.revision !== saved.revision) throw new DashboardError("The connection changed. Preview and save again.", 409);
    const count = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_queries WHERE id <> $1", [id]);
    if (count.rows[0].count >= 24) throw new DashboardError("This dashboard supports up to 24 saved queries.");
    await client.query(`INSERT INTO elastic_dashboard_queries (id, definition, result, refreshed_at, attempted_at, next_attempt)
      VALUES ($1, $2::jsonb, $3::jsonb, now(), now(), now() + $4 * interval '1 minute')
      ON CONFLICT (id) DO UPDATE SET definition = EXCLUDED.definition, result = EXCLUDED.result,
      revision = elastic_dashboard_queries.revision + 1, refreshed_at = now(), attempted_at = now(),
      next_attempt = EXCLUDED.next_attempt, last_error = NULL`,
      [id, JSON.stringify(definition), JSON.stringify(result), definition.refreshMinutes]);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action, query_id) VALUES ($1, 'query.saved', $2)", [actor, id]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

async function refreshQueries(force = false): Promise<void> {
  if (!elasticVulnEnabled()) return;
  const saved = await connection();
  if (!saved) return;
  const db = await database();
  const due = await db.query(`SELECT id, definition, revision FROM elastic_dashboard_queries
    WHERE (definition->>'enabled')::boolean = true
    AND (next_attempt <= now() OR ($1 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds')))
    ORDER BY next_attempt LIMIT 24`, [force]);
  for (const row of due.rows) {
    const definition = parseDefinition(row.definition, row.id);
    // Atomic claim across app instances. A refresh never erases the last success.
    const claim = await db.query(`UPDATE elastic_dashboard_queries SET attempted_at = now(),
      next_attempt = now() + $3 * interval '1 minute'
      WHERE id = $1 AND revision = $2 AND (next_attempt <= now() OR
      ($4 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds'))) RETURNING id`,
      [row.id, row.revision, definition.refreshMinutes, force]);
    if (!claim.rowCount) continue;
    let result: QueryResult | null = null;
    let error: string | null = null;
    try {
      result = await limitedQuery(saved.value, definition.query);
      validateDisplayResult(result, definition);
    } catch (err) {
      result = null;
      error = err instanceof DashboardError ? err.message : "Elastic refresh failed. Check the connection and query, then retry.";
    }
    await db.query(`UPDATE elastic_dashboard_queries SET
      result = CASE WHEN $3::jsonb IS NULL THEN result ELSE $3::jsonb END,
      refreshed_at = CASE WHEN $3::jsonb IS NULL THEN refreshed_at ELSE now() END,
      last_error = $4
      WHERE id = $1 AND revision = $2 AND EXISTS
      (SELECT 1 FROM elastic_dashboard_connection WHERE id = 1 AND revision = $5)`,
      [row.id, row.revision, result ? JSON.stringify(result) : null, error, saved.revision]);
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
