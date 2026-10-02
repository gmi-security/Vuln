import { Pool } from "pg";
import { applicationDatabase } from "./persist";
import { elasticJsonRequest, openConnection, type ElasticConnection } from "./elastic-query-client";
import { validateQuery } from "./elastic-dashboard";

// Deliberately not lib/elastic-dashboard-store.ts's dashboardDatabase():
// that module's import graph (crowdstrike-dashboard-client,
// dashboard-daily-trend, dashboard-query-connectors, ...) is the whole
// dashboard-tile system, far more than this needs, and pulling it into
// lib/store.ts's already-massive import graph broke the hand-rolled mock
// loaders a couple of tests use. This mirrors just its pool-selection
// logic: a dedicated pool when ELASTIC_VULN_DATABASE_URL is set (the
// elastic_dashboard_connection table can live in a separate DB from the
// rest of the app -- see risk-scoring-store.ts's long comment on this
// exact two-database split), else the main app pool.
let dedicatedPool: Pool | undefined;
function connectionDatabase(): Pool | null {
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (url) {
    dedicatedPool ??= new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000, statement_timeout: 5000 });
    return dedicatedPool;
  }
  return applicationDatabase();
}

// assetCoverage()'s Postgres merge (lib/risk-scoring-store.ts's
// getScannedHostnamesByCompany) can only mark a host "scanned" if it
// currently has at least one risk-scored finding -- finding_risk is
// finding-level, not asset-level. A fully patched, zero-open-finding
// managed endpoint never appears there and would still show as a
// coverage gap. CrowdStrike's own discover_asset index is asset-level
// (one row per device, entity_type: managed/unmanaged/unsupported) and
// closes that gap -- a host it calls "managed" has a live Falcon sensor
// regardless of whether it currently has open findings.
//
// This bypasses the dashboard tile system entirely (lib/elastic-dashboard-store.ts's
// limitedQuery/executeEsql hard-appends "| LIMIT 101", fine for a tile,
// useless for an asset list) and reads the same stored connection
// directly. Best-effort throughout: Coverage must never break because
// Elastic isn't configured or a query fails.
async function getElasticConnection(): Promise<ElasticConnection | null> {
  const db = connectionDatabase();
  if (!db) return null;
  // The table is created by lib/elastic-dashboard-store.ts's own
  // dashboardDatabase() the first time the Reporting dashboard is used; a
  // missing table here just means Elastic was never connected, same as a
  // missing row.
  const result = await db.query("SELECT secret FROM elastic_dashboard_connection WHERE id = 1").catch(() => null);
  if (!result?.rows.length) return null;
  return openConnection(result.rows[0].secret);
}

export type ManagedHost = { cid: string; hostname: string };

const MANAGED_HOSTS_QUERY = `FROM logs-crowdstrike.discover_asset-*
| WHERE entity_type == "managed" AND hostname IS NOT NULL AND hostname != ""
| STATS BY cid, hostname
| LIMIT 10000`;

// Deliberately not lib/elastic-dashboard.ts's parseQueryResult(): that
// enforces a 32-column/101-row cap meant for dashboard tiles, which this
// query (potentially thousands of managed hosts) would always exceed.
// Elasticsearch's raw ES|QL response shape is { columns, values }.
export async function getManagedHostnames(): Promise<ManagedHost[]> {
  const connection = await getElasticConnection();
  if (!connection) return [];
  const reply = await elasticJsonRequest(connection, "/_query?format=json&allow_partial_results=false", "POST", {
    query: validateQuery(MANAGED_HOSTS_QUERY), columnar: false,
  });
  if (reply.warning) throw new Error("Elastic returned a partial/warning result for managed-host coverage.");
  const columns = reply.body.columns;
  const values = reply.body.values;
  if (!Array.isArray(columns) || !Array.isArray(values)) return [];
  const cidIdx = columns.findIndex((c) => c && typeof c === "object" && (c as { name?: string }).name === "cid");
  const hostIdx = columns.findIndex((c) => c && typeof c === "object" && (c as { name?: string }).name === "hostname");
  if (cidIdx === -1 || hostIdx === -1) return [];
  const out: ManagedHost[] = [];
  for (const row of values) {
    if (!Array.isArray(row)) continue;
    const cid = row[cidIdx], hostname = row[hostIdx];
    if (typeof cid === "string" && typeof hostname === "string" && cid && hostname) {
      out.push({ cid, hostname });
    }
  }
  return out;
}
