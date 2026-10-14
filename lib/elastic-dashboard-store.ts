import { checkReviewedElasticConnection } from "./customer-elastic-query";
import { assertStoredSpotlightPacketScope, type StoredSpotlightPacket } from "./customer-stored-spotlight";
import { assertPatchCid, type QueryScopeProof } from "./customer-query-scope";
import { parsePatchInput, parseConsolidationInput } from "./patch-request";
import { loadReviewedQueryRoutes, selectQueryRoute, recheckQueryRoute } from "./customer-query-routing-server";
import { reviewedQueryRouting, type QueryRoute } from "./customer-query-routing";
import { validateDashboardCustomer } from "./dashboard-customer";
import { customerReportingTileIds, reportingTileCompanyId } from "./reporting-direct-sources";
import { Pool, type PoolClient } from "pg";
import { randomUUID, createHash } from "node:crypto";
import { applicationDatabase } from "./persist";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DEFAULT_COVERAGE, DashboardError, validateDisplayResult, parseDefinition,
  parseQueryInput, querySource, type QueryInput, type DashboardSource,
  type DashboardQuery, type ElasticDashboard, type QueryResult } from "./elastic-dashboard";
import { normalizeEndpoint, sealConnection, type ElasticConnection } from "./elastic-query-client";
import { DASHBOARD_CONNECTORS } from "./dashboard-query-connectors";
import { executePatchConsolidation, executePatchRequest, parseCrowdStrikeConnection, sealCrowdStrike, testCrowdStrikeConnection, verifyPatchFix } from "./crowdstrike-dashboard-client";
import { type CrowdStrikeConnection } from "./crowdstrike-dashboard";
import { installDailyOpenVulnerabilityTile } from "./dashboard-daily-trend";
import { installExprtRankedCveTile } from "./dashboard-exprt-tile";

let dedicatedPool: Pool | undefined;
let ready: Promise<void> | undefined;
const runtime = globalThis as typeof globalThis & {
  __elasticDashboard?: { timer?: ReturnType<typeof setInterval>; ticking?: Promise<void>; running: number; previews: Map<string, number> };
};
const state: NonNullable<typeof runtime.__elasticDashboard> = runtime.__elasticDashboard ??= { running: 0, previews: new Map<string, number>() };

export async function dashboardDatabase(): Promise<Pool> {
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (url && !dedicatedPool) {
    dedicatedPool = new Pool({ connectionString: url, ...(process.env.VULN_RUNTIME_ROLE === "web" ? { options: "-c default_transaction_read_only=on" } : {}), max: 2, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000, statement_timeout: 5000 });
    dedicatedPool.on("error", () => {
      const old = dedicatedPool;
      dedicatedPool = undefined;
      ready = undefined;
      void old?.end().catch(() => {});
    });
  }
  const db = url ? dedicatedPool : applicationDatabase();
  if (!db) throw new DashboardError("Dashboard storage is not configured.", 503);
  if (process.env.VULN_RUNTIME_ROLE === "web") return db;
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
      ALTER TABLE elastic_dashboard_queries ADD COLUMN IF NOT EXISTS display_order INTEGER;
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
      await installDailyOpenVulnerabilityTile(db);
      await installExprtRankedCveTile(db);
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

export async function readDashboard(canManage: boolean, companyId?: string): Promise<ElasticDashboard> {
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
    const configured = process.env.REPORTING_CUSTOMER_TILE_IDS ?? "", atlasIds = process.env.ATLAS_REPORTING_TILE_IDS ?? "";
    const legacyIds = companyId ? customerReportingTileIds(companyId,configured,atlasIds) : [];
    const rows = await db.query(`SELECT * FROM elastic_dashboard_queries WHERE deleted_at IS NULL
      AND ($1::text IS NULL OR definition->>'companyId' = $1 OR
        (NOT (definition ? 'companyId') AND id = ANY($2::text[])))
      ORDER BY display_order NULLS LAST, id = 'asset-coverage' DESC, id`,[companyId ?? null,legacyIds]);
    const definitions = companyId && canManage ? (await db.query("SELECT id, definition FROM elastic_dashboard_queries WHERE deleted_at IS NULL AND definition->>'companyId' IS NULL")).rows : [];
    const unassignedTiles = definitions.filter(row=>!reportingTileCompanyId({...row.definition,id:row.id},configured,atlasIds))
      .map(row=>({id:row.id,title:row.definition.title,source:querySource(row.definition)}));
    const routeSets: Record<DashboardSource, { routes: QueryRoute[] | null; error: string }> = {
      elastic: { routes: null, error: "" }, crowdstrike: { routes: null, error: "" },
    };
    for (const source of ["elastic", "crowdstrike"] as const) {
      try { routeSets[source].routes = await loadReviewedQueryRoutes(db, source); }
      catch { routeSets[source].error = `Customer query routing needs renewed approval. Cached ${DASHBOARD_CONNECTORS[source].label} results are withheld.`; }
    }
    const queries = rows.rows.map(row => {
      const owner = reportingTileCompanyId({ ...row.definition, id: row.id }, configured, atlasIds);
      const source = querySource(row.definition), { routes, error: routeError } = routeSets[source], active = source === "elastic" ? saved : falcon;
      let result = row.result, error = row.last_error;
      try {
        if (routeError) throw new DashboardError(routeError, 503);
        if (routes !== null && !active) throw new DashboardError(`Connect the approved ${DASHBOARD_CONNECTORS[source].label} connection before showing results.`, 409);
        const route = selectQueryRoute(routes, owner, undefined, active?.revision, source);
        if (route && result?.scopeKey !== route.bindingKey) { result = null; error = "Waiting for results collected under this customer's current query approval."; }
      } catch (cause) { result = null; error = cause instanceof DashboardError ? cause.message : "Customer query routing is unavailable."; }
      return { ...row.definition, companyId: owner, result, refreshedAt: result ? row.refreshed_at?.toISOString() ?? null : null,
        attemptedAt: row.attempted_at?.toISOString() ?? null, error };
    });
    const available = (source: DashboardSource) => {
      const active = source === "elastic" ? saved : falcon, { routes, error } = routeSets[source];
      return Boolean(active) && !error && (routes === null || routes.some(r => r.companyId === companyId && r.connectionRevision === active?.revision));
    };
    return {
      canManage, storageReady: true, connected: Boolean(saved),
      ...(canManage && saved ? { endpoint: (saved.value as ElasticConnection).endpoint } : {}),
      crowdstrike: { connected: Boolean(falcon), ...(canManage && falcon ? { region: (falcon.value as CrowdStrikeConnection).region } : {}) },
      ...(companyId && canManage ? {availableSources:{elastic:available("elastic"),crowdstrike:available("crowdstrike")},unassignedTiles} : {}),
      queries,
    };
  } catch {
    return { canManage, storageReady: false, connected: false, queries: [emptyQuery()] };
  }
}

async function limitedQuery(saved: unknown, query: string | QueryInput, async = true, revision?: number): Promise<QueryResult> {
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  const input = typeof query === "string" ? { query } : query;
  try {
    const db = await database();
    const source = querySource(input);
    const route = selectQueryRoute(await loadReviewedQueryRoutes(db, source), input.companyId, undefined, revision, source);
    const result = await DASHBOARD_CONNECTORS[source].execute(saved, input, async, source === "crowdstrike" ? route?.sourceScope : undefined,
      source === "elastic" && route ? JSON.parse(route.sourceScope) : undefined);
    await recheckQueryRoute(db, route);
    return route ? { ...result, scopeKey: route.bindingKey } : result;
  } finally { state.running--; }
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
  if (id && input.companyId === undefined) {
    const row = (await (await database()).query("SELECT definition FROM elastic_dashboard_queries WHERE id=$1 AND deleted_at IS NULL", [id])).rows[0];
    if (row) input.companyId = reportingTileCompanyId({ ...row.definition, id }, process.env.REPORTING_CUSTOMER_TILE_IDS, process.env.ATLAS_REPORTING_TILE_IDS);
  }
  const saved = await connection(querySource(input));
  if (!saved) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[querySource(input)].label} first.`, 409);
  const result = await limitedQuery(saved.value, input, true, saved.revision);
  return historyResult(await database(), input, id ?? "preview", saved.revision, result, false);
}

// The signature prevents edits to the population or measure from mixing history.
export function historySignature(input: QueryInput, scopeKey?: string): string {
  return createHash("sha256").update(JSON.stringify({ source: querySource(input), query: input.query,
    ...(scopeKey ? { scopeKey, companyId: input.companyId } : {}), dataset: input.crowdstrike?.dataset, measure: input.crowdstrike?.measure, group: input.crowdstrike?.groupBy })).digest("hex");
}

async function historyResult(db: Pool | PoolClient, input: QueryInput, id: string, revision: number, result: QueryResult, save: boolean): Promise<QueryResult> {
  if (querySource(input) !== "crowdstrike" || !input.crowdstrike?.history) return result;
  const signature = historySignature(input, result.scopeKey), today = new Date().toISOString().slice(0, 10), value = result.rows[0]?.[0];
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
  return { ...(result.scopeKey ? { scopeKey: result.scopeKey } : {}), columns: [{ name: "day", type: "date" }, { name: input.crowdstrike.measure, type: "long" }], rows: values, truncated: false,
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
  // Reviewed connections are saved before dataset approval. Check authentication
  // and deployment metadata without reading an unassigned customer's findings.
  if (reviewedQueryRouting(process.env.VULN_REVIEWED_QUERY_PROVIDERS, "elastic")) await checkReviewedElasticConnection(candidate);
  else await limitedQuery(candidate, DEFAULT_COVERAGE.query, false);
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

export async function assertQueryResultScope(input: QueryInput & { id?: string }, result: QueryResult) {
  const source = querySource(input);
  const db = await database(), routes = await loadReviewedQueryRoutes(db, source);
  if (routes === null) return;
  let companyId = input.companyId;
  if (companyId === undefined && input.id) {
    const row = (await db.query("SELECT definition FROM elastic_dashboard_queries WHERE id=$1 AND deleted_at IS NULL", [input.id])).rows[0];
    if (row) companyId = reportingTileCompanyId({ ...row.definition, id: input.id }, process.env.REPORTING_CUSTOMER_TILE_IDS, process.env.ATLAS_REPORTING_TILE_IDS);
  }
  const route = selectQueryRoute(routes, companyId, undefined, undefined, source);
  if (route && result.scopeKey !== route.bindingKey) throw new DashboardError("Customer query approval changed. Preview again.", 409);
}

function queryProof(route: QueryRoute): QueryScopeProof {
  return { companyId: route.companyId, cid: route.sourceScope, bindingKey: route.bindingKey, connectionRevision: route.connectionRevision };
}
// Saved reports remain available as history. Only a current reviewed proof can
// authorize a new live ticket/verification once reviewed routing is enabled.
export async function assertPatchRequestScope(packet: StoredSpotlightPacket & { queryScope?: QueryScopeProof; tenantIds?: string[] }, revision?: number) {
  if (packet.source === "stored-findings") return assertStoredSpotlightPacketScope(packet);
  const routes = await loadReviewedQueryRoutes(await database());
  if (routes === null) return;
  const proof = packet.queryScope;
  if (!proof || packet.appCompanyId !== proof.companyId) throw new DashboardError("Prepare a fresh customer-scoped patch report before sending or verifying.", 409);
  const route = selectQueryRoute(routes, proof.companyId, proof.cid, revision ?? proof.connectionRevision)!;
  if (route.bindingKey !== proof.bindingKey) throw new DashboardError("Customer patch approval changed. Prepare a fresh report.", 409);
  assertPatchCid(packet.hostScope ?? [], packet.tenantIds ?? (packet.tenantId ? [packet.tenantId] : []), route.sourceScope);
}
export async function preparePatchRequest(value: unknown, revision: number, alreadyTicketed: Set<string> = new Set()) {
  const input = parsePatchInput(value), saved = await connection("crowdstrike"), db = await database();
  if (!saved || saved.revision !== revision) throw new DashboardError("The CrowdStrike connection changed. Prepare the request again.", 409);
  const route = selectQueryRoute(await loadReviewedQueryRoutes(db), input.appCompanyId, input.tenantId, revision);
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  try {
    const packet = await executePatchRequest(saved.value as CrowdStrikeConnection, route ? { ...input, tenantId: route.sourceScope } : input, alreadyTicketed);
    await recheckQueryRoute(db, route);
    if (route) { assertPatchCid(packet.hostScope, packet.tenantIds, route.sourceScope); packet.appCompanyId = route.companyId; packet.queryScope = queryProof(route); }
    return packet;
  } finally { state.running--; }
}
export async function prepareConsolidation(value: unknown, revision: number, alreadyTicketed: Set<string> = new Set()) {
  const input = parseConsolidationInput(value), saved = await connection("crowdstrike"), db = await database();
  if (!saved || saved.revision !== revision) throw new DashboardError("The CrowdStrike connection changed. Prepare the consolidation again.", 409);
  const route = selectQueryRoute(await loadReviewedQueryRoutes(db), input.appCompanyId, input.tenantId, revision);
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  try {
    const packet = await executePatchConsolidation(saved.value as CrowdStrikeConnection, route ? { ...input, tenantId: route.sourceScope, appCompanyId: route.companyId } : input, alreadyTicketed);
    await recheckQueryRoute(db, route);
    if (route) {
      assertPatchCid([], packet.tenantIds, route.sourceScope);
      packet.appCompanyId = route.companyId; packet.queryScope = queryProof(route);
      for (const group of packet.groups) {
        assertPatchCid(group.hostScope, [group.tenantId, ...group.deviceCves.map(d => d.cid)], route.sourceScope);
        group.appCompanyId = route.companyId; group.queryScope = queryProof(route);
      }
    }
    return packet;
  } finally { state.running--; }
}
export async function verifyAgainstCrowdStrike(cves: string[], hostScope: string[], tenantId: string, revision: number, packet?: { appCompanyId?: string; queryScope?: QueryScopeProof }) {
  const saved = await connection("crowdstrike"), db = await database();
  if (!saved || saved.revision !== revision) throw new DashboardError("The CrowdStrike connection changed. Prepare a fresh report before verifying.", 409);
  const route = selectQueryRoute(await loadReviewedQueryRoutes(db), packet?.appCompanyId, tenantId, revision);
  if (route) await assertPatchRequestScope({ ...packet, hostScope, tenantId }, revision);
  if (state.running >= 2) throw new DashboardError("Two queries are already running. Try again shortly.", 429);
  state.running++;
  try {
    const result = await verifyPatchFix(saved.value as CrowdStrikeConnection, cves, hostScope, tenantId);
    await recheckQueryRoute(db, route);
    return result;
  } finally { state.running--; }
}

// Save settings first. Remote validation and execution belong to the refresh
// worker, so adding a tile never waits for Elastic/CrowdStrike or the job queue.
export async function addDashboardTile(value: unknown, actor: string, customerScope?: string): Promise<{ saved: true; query: DashboardQuery }> {
  const body = value as Record<string, unknown>;
  const id = typeof body?.id === "string" ? body.id : randomUUID();
  const definition = parseDefinition(customerScope ? {...body,companyId:customerScope} : body, id), source = querySource(definition);
  const withheld = reviewedQueryRouting(process.env.VULN_REVIEWED_QUERY_PROVIDERS, source);
  if (definition.companyId) await validateDashboardCustomer(definition.companyId);
  const db = await database(), client = await db.connect();
  let tile: DashboardQuery;
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const connected = source === "elastic" ? await client.query("SELECT id FROM elastic_dashboard_connection WHERE id = 1") :
      await client.query("SELECT source FROM dashboard_source_connections WHERE source = $1", [source]);
    if (!connected.rowCount) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[source].label} first.`, 409);
    const previous = (await client.query("SELECT definition, result, refreshed_at, deleted_at FROM elastic_dashboard_queries WHERE id = $1", [id])).rows[0];
    const previousCompany = previous ? reportingTileCompanyId({ ...previous.definition,id },process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) : null;
    if (customerScope && previous && previousCompany !== customerScope) throw new DashboardError("This tile does not belong to the selected customer.",409);
    // Older clients omit ownership; never silently unassign an existing tile.
    if (definition.companyId === undefined) definition.companyId = previousCompany;
    if (previous && definition.companyId !== previousCompany) throw new DashboardError("Use the customer report to attach an unassigned tile.",409);
    if (previous?.deleted_at) throw new DashboardError("This tile was deleted. Add a new tile instead.", 409);
    const count = await client.query("SELECT count(*)::int AS count FROM elastic_dashboard_queries WHERE id <> $1 AND deleted_at IS NULL", [id]);
    if (count.rows[0].count >= 24) throw new DashboardError("This dashboard supports up to 24 saved queries.");
    let result: QueryResult | null = null, refreshedAt: string | null = null;
    if (previous?.result && JSON.stringify(parseQueryInput({ ...previous.definition, companyId: previousCompany })) === JSON.stringify(parseQueryInput(definition))) {
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
    // Preserve cache in storage, but the immediate save response must not expose
    // it before readDashboard checks the current approval. Saving stays local.
    tile = { ...definition, result: withheld ? null : result, refreshedAt: withheld ? null : refreshedAt, attemptedAt: null, error: null };
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh(false,customerScope ? [id] : undefined);
  return { saved: true, query: tile };
}

export async function assignDashboardTile(id: string, companyId: string, actor: string) {
  await validateDashboardCustomer(companyId);
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(id)) throw new DashboardError("Invalid tile ID.");
  const db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const row = (await client.query("SELECT definition FROM elastic_dashboard_queries WHERE id = $1 AND deleted_at IS NULL",[id])).rows[0];
    if (!row) throw new DashboardError("Tile not found.",404);
    const owner = reportingTileCompanyId({...row.definition,id},process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS);
    if (owner && owner !== companyId) throw new DashboardError("This tile already belongs to another customer.",409);
    await client.query(`UPDATE elastic_dashboard_queries SET definition = jsonb_set(definition,'{companyId}',to_jsonb($2::text)),
      revision = revision + 1, refresh_lease_until = NULL WHERE id = $1`,[id,companyId]);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action, query_id) VALUES ($1,$2,$3)",[actor,`query.customer.assigned:${companyId}`,id]);
    await client.query("COMMIT");
    return {saved:true};
  } catch(error) {await client.query("ROLLBACK");throw error;} finally {client.release();}
}

export async function reorderDashboardTiles(value: unknown, actor: string, customerScope?: string): Promise<void> {
  if (customerScope) await validateDashboardCustomer(customerScope);
  const ids = (value as { ids?: unknown } | null)?.ids;
  if (!Array.isArray(ids) || ids.length > 24 || ids.some((id) => typeof id !== "string" || !/^[a-zA-Z0-9-]{1,64}$/.test(id)) || new Set(ids).size !== ids.length) {
    throw new DashboardError("Supply each tile ID once in the desired order.");
  }
  const db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const active = await client.query("SELECT id, definition FROM elastic_dashboard_queries WHERE deleted_at IS NULL");
    const expected = new Set(active.rows.filter(row=>!customerScope || reportingTileCompanyId({...row.definition,id:row.id},process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) === customerScope).map(row=>row.id));
    if (ids.length !== expected.size || ids.some((id) => !expected.has(id))) {
      throw new DashboardError("The tiles changed while you were arranging them. Refresh the dashboard and try again.", 409);
    }
    await client.query(`UPDATE elastic_dashboard_queries AS tile SET display_order = ordered.position::int
      FROM unnest($1::text[]) WITH ORDINALITY AS ordered(id, position)
      WHERE tile.id = ordered.id AND tile.deleted_at IS NULL`, [ids]);
    await client.query("INSERT INTO elastic_dashboard_audit (actor, action) VALUES ($1, 'layout.reordered')", [actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
}

export async function deleteDashboardTile(id: string, actor: string, customerScope?: string): Promise<void> {
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(id)) throw new DashboardError("Invalid tile ID.");
  const db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    if (customerScope) {
      const row = (await client.query("SELECT definition FROM elastic_dashboard_queries WHERE id = $1 AND deleted_at IS NULL",[id])).rows[0];
      if (!row || reportingTileCompanyId({...row.definition,id},process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) !== customerScope)
        throw new DashboardError("This tile does not belong to the selected customer.",409);
    }
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
  if (definition.companyId) await validateDashboardCustomer(definition.companyId);
  if (definition.companyId === undefined) {
    const row = (await (await database()).query("SELECT definition FROM elastic_dashboard_queries WHERE id=$1 AND deleted_at IS NULL", [id])).rows[0];
    if (row) definition.companyId = reportingTileCompanyId({ ...row.definition, id }, process.env.REPORTING_CUSTOMER_TILE_IDS, process.env.ATLAS_REPORTING_TILE_IDS);
  }
  const source = querySource(definition), saved = await connection(source);
  if (!saved) throw new DashboardError(`Connect ${DASHBOARD_CONNECTORS[source].label} first.`, 409);
  if (!job) throttlePreview(actor);
  const rawResult = await limitedQuery(saved.value, definition, true, saved.revision);
  const db = await database();
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const current = source === "elastic" ? await client.query("SELECT revision FROM elastic_dashboard_connection WHERE id = 1") :
      await client.query("SELECT revision FROM dashboard_source_connections WHERE source = $1", [source]);
    if (current.rows[0]?.revision !== saved.revision) throw new DashboardError("The connection changed. Preview and save again.", 409);
    const existing = (await client.query("SELECT definition, deleted_at FROM elastic_dashboard_queries WHERE id = $1", [id])).rows[0];
    const owner = existing ? reportingTileCompanyId({...existing.definition,id},process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) : null;
    if (definition.companyId === undefined) definition.companyId = owner;
    if (existing && definition.companyId !== owner) throw new DashboardError("The tile customer changed. Reload and save again.",409);
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

async function refreshQueries(force = false, ids?: string[], companyId?: string): Promise<void> {
  if (!elasticVulnEnabled()) return;
  const db = await database();
  const due = await db.query(`SELECT id, definition, revision FROM elastic_dashboard_queries
    WHERE deleted_at IS NULL AND ((definition->>'enabled')::boolean = true OR refresh_requested = true OR $1)
    AND ($2::text[] IS NULL OR id = ANY($2::text[]))
    AND ($3::text IS NULL OR refresh_requested=true)
    AND (refresh_lease_until IS NULL OR refresh_lease_until <= now())
    AND (next_attempt <= now() OR ($1 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds')))
    ORDER BY next_attempt LIMIT 24`, [force,ids ?? null,companyId ?? null]);
  for (const row of due.rows) {
    // Leave pending tiles due while previews occupy the execution slots.
    if (companyId) {
      // Manual requests remain pending while previews occupy both slots, even
      // when the general scheduler is paused. No DB connection is held here.
      while (state.running >= 2) await new Promise<void>(resolve=>setTimeout(resolve,500));
    } else if (state.running >= 2) break;
    const definition = parseDefinition(row.definition, row.id);
    definition.companyId = reportingTileCompanyId({ ...definition, id: row.id }, process.env.REPORTING_CUSTOMER_TILE_IDS, process.env.ATLAS_REPORTING_TILE_IDS);
    if (companyId && definition.companyId !== companyId) continue;
    let saved;
    try { saved = await connection(querySource(definition)); }
    catch (error) {
      if (!(error instanceof DashboardError)) throw error;
      await db.query(`UPDATE elastic_dashboard_queries SET last_error = $3, attempted_at = now(), refresh_requested = false,
        next_attempt = now() + $4 * interval '1 minute' WHERE id = $1 AND revision = $2`,
        [row.id, row.revision, error.message, definition.refreshMinutes]);
      continue;
    }
    if (!saved) {
      if (companyId) await db.query(`UPDATE elastic_dashboard_queries SET last_error='Source connection is not configured.',
        attempted_at=now(),refresh_requested=false WHERE id=$1 AND revision=$2`,[row.id,row.revision]);
      continue;
    }
    if (companyId) {
      while (state.running >= 2) await new Promise<void>(resolve=>setTimeout(resolve,500));
    } else if (state.running >= 2) break;
    // Atomic claim across app instances. A refresh never erases the last success.
    const claim = await db.query(`UPDATE elastic_dashboard_queries SET attempted_at = now(), refresh_requested = false,
      next_attempt = now() + $3 * interval '1 minute', refresh_lease_until = now() + interval '7 minutes'
      WHERE id = $1 AND revision = $2 AND ($5::text IS NULL OR refresh_requested=true)
      AND (refresh_lease_until IS NULL OR refresh_lease_until <= now()) AND (next_attempt <= now() OR
      ($4 AND (attempted_at IS NULL OR attempted_at < now() - interval '30 seconds'))) RETURNING id`,
      [row.id, row.revision, definition.refreshMinutes, force,companyId ?? null]);
    if (!claim.rowCount) continue;
    let result: QueryResult | null = null;
    let error: string | null = null;
    try {
      result = await limitedQuery(saved.value, definition, true, saved.revision);
    } catch (err) {
      if (err instanceof DashboardError && err.status === 429 && state.running >= 2) {
        await db.query(`UPDATE elastic_dashboard_queries SET refresh_requested = true,
          refresh_lease_until = NULL, next_attempt = now() WHERE id = $1 AND revision = $2`, [row.id, row.revision]);
        if (companyId) void state.ticking?.then(()=>triggerRefresh(force,ids,companyId));
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

export async function requestCustomerQueryRefresh(companyId: string, id: string, actor: string): Promise<void> {
  await validateDashboardCustomer(companyId);
  const db = await database(), client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804201)");
    const row = (await client.query("SELECT definition,revision FROM elastic_dashboard_queries WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",[id])).rows[0];
    if (!row || reportingTileCompanyId({...row.definition,id},process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) !== companyId)
      throw new DashboardError("This query no longer belongs to the selected customer.",409);
    const requested = await client.query(`UPDATE elastic_dashboard_queries SET refresh_requested=true,next_attempt=now()
      WHERE id=$1 AND revision=$2
      AND (refresh_lease_until IS NULL OR refresh_lease_until<=now())
      AND (attempted_at IS NULL OR attempted_at<now()-interval '30 seconds') RETURNING id`,[id,row.revision]);
    if (!requested.rowCount) throw new DashboardError("This query is running or was just refreshed. Check status before retrying.",409);
    await client.query("INSERT INTO elastic_dashboard_audit(actor,action,query_id) VALUES($1,'query.refresh.requested',$2)",[actor,id]);
    await client.query("COMMIT");
  } catch(error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  triggerRefresh(true,[id],companyId);
}

export function triggerRefresh(force = false, ids?: string[], companyId?: string): void {
  if (process.env.VULN_RUNTIME_ROLE === "web") return;
  if (ids?.length === 0) return;
  if (state.ticking) {
    // Preserve the customer's requested scope while another pass completes.
    if (ids) void state.ticking.then(()=>triggerRefresh(force,ids,companyId));
    return;
  }
  state.ticking = refreshQueries(force,ids,companyId).catch(() => {
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
