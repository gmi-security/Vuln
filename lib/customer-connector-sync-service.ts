import type { Pool, PoolClient } from "pg";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { customerDashboardPool, readCustomerConnectorStatus } from "./customer-connector-status-service";
import { readSavedApplicationCompanies } from "./db/connector-metadata.mjs";
import { customerSyncRows, requireSyncAction, type CustomerSyncStatus, type ImportSyncRecord, type QuerySyncRecord } from "./customer-connector-sync-model";
import { reportingTileCompanyId } from "./reporting-direct-sources";
import { falconConfigs } from "./crowdstrike";
import { selectSpotlightTenant, selectReviewedSpotlightTenant } from "./spotlight-import";
import { loadReviewedSpotlightRoutes } from "./customer-spotlight-routing-server";
import { ensureHydrated, getCsSpotlightSyncStatus, startCsSpotlightSync } from "./store";
import { defenderStore } from "./defender-store";
import { triggerDefenderWorker } from "./defender-worker";
import { requestCustomerQueryRefresh } from "./elastic-dashboard-store";

async function readOnly<T>(pool: Pool, read: (client: PoolClient)=>Promise<T>) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL statement_timeout='10s'");
    await client.query("SET LOCAL lock_timeout='2s'");
    const result = await read(client);
    await client.query("COMMIT"); return result;
  } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; }
  finally { client.release(); }
}
async function present(client: PoolClient, table: string) {
  return !!(await client.query("SELECT to_regclass($1) AS name",[`public.${table}`])).rows[0]?.name;
}
export async function readOwnedQuerySync(client: PoolClient, companyId: string): Promise<QuerySyncRecord[]> {
  if (!await present(client,"elastic_dashboard_queries")) return [];
  // Read metadata only, never query text, results, credentials or host records.
  const rows = (await client.query(`SELECT id,definition->>'title' AS title,COALESCE(definition->>'source','elastic') AS source,
    definition->>'companyId' AS "companyId",definition ? 'companyId' AS "hasOwner",refreshed_at,attempted_at,refresh_lease_until,refresh_requested,
    CASE WHEN last_error IS NOT NULL THEN 'failed' ELSE NULL END AS last_error
    FROM elastic_dashboard_queries WHERE deleted_at IS NULL ORDER BY display_order,id LIMIT 1001`)).rows;
  if (rows.length > 1000) throw new DashboardError("Too many saved queries to display sync status.",503);
  return rows.map(row=>({...row,companyId:row.hasOwner ? row.companyId : undefined})).filter(row=>["elastic","crowdstrike"].includes(row.source) && reportingTileCompanyId(row,
    process.env.REPORTING_CUSTOMER_TILE_IDS,process.env.ATLAS_REPORTING_TILE_IDS) === companyId);
}
export async function readCustomerSyncStatus(companyId: string): Promise<CustomerSyncStatus> {
  const configuration = await readCustomerConnectorStatus(companyId);
  if (!("items" in configuration)) throw new DashboardError("Choose an existing customer.");
  const app = applicationDatabase();
  if (!app) throw new DashboardError("Sync status storage is unavailable.",503);
  const client = await app.connect();
  let companies;
  try { companies = await readSavedApplicationCompanies(client); } finally { client.release(); }
  let spotlightAvailable = false, spotlightLabel: string | undefined;
  try {
    const routes = await loadReviewedSpotlightRoutes("crowdstrike");
    const selection = routes === null ? selectSpotlightTenant(falconConfigs(),companies,companyId)
      : selectReviewedSpotlightTenant(falconConfigs(),companies,routes,companyId);
    spotlightAvailable = true; spotlightLabel = selection.config.label;
  } catch { /* Saved evidence alone is not a runnable connection. */ }
  const imports = await readOnly(app,async db=> {
    let defender: ImportSyncRecord | null = null, spotlight: ImportSyncRecord | null = null;
    if (await present(db,"defender_connections") && await present(db,"defender_import_runs")) {
      defender = (await db.query(`SELECT c.last_success_at,r.status,r.started_at,r.lease_until,r.fetched
        FROM defender_connections c LEFT JOIN LATERAL (
          SELECT status,started_at,lease_until,fetched FROM defender_import_runs WHERE company_id=c.company_id ORDER BY started_at DESC LIMIT 1
        ) r ON true WHERE c.company_id=$1`,[companyId])).rows[0] ?? null;
    }
    if (await present(db,"spotlight_import_runs") && await present(db,"spotlight_import_current")) {
      spotlight = (await db.query(`SELECT r.status,r.started_at,r.hydrated_count,
        (SELECT c.promoted_at FROM spotlight_import_current c WHERE c.tenant_key=$1) AS last_success_at
        FROM spotlight_import_runs r WHERE r.tenant_key=$1 ORDER BY r.started_at DESC LIMIT 1`,[companyId])).rows[0] ?? null;
    }
    return {defender,spotlight};
  });
  const queries = await readOnly(customerDashboardPool(app),db=>readOwnedQuerySync(db,companyId));
  const active = getCsSpotlightSyncStatus();
  return {companyId,checkedAt:new Date().toISOString(),schedulerPaused:process.env.VULN_DISABLE_SCHEDULER === "true",
    rows:customerSyncRows({companyId,providers:configuration.items.map(item=>item.provider),...imports,queries,now:Date.now(),
      spotlightAvailable,spotlightBusy:active.running,spotlightActive:active.running && spotlightAvailable && active.tenant === spotlightLabel})};
}
export async function startCustomerSync(companyId: string, id: string, actor: string) {
  const status = await readCustomerSyncStatus(companyId);
  try { requireSyncAction(status,id); }
  catch(error) { throw new DashboardError(error instanceof Error ? error.message : "Sync is unavailable.",409); }
  if (id === "defender") {
    const runId = await defenderStore().enqueue(companyId,actor);
    void triggerDefenderWorker(companyId);
    return {queued:true,runId};
  }
  if (id === "crowdstrike-spotlight") {
    await ensureHydrated();
    const launch = await startCsSpotlightSync(companyId);
    if (!launch.started) throw new DashboardError("Spotlight could not start. Its worker may be busy or the customer mapping may have changed. Refresh status and retry.",409);
    return {queued:true};
  }
  // The worker rechecks ownership before claiming each query. Do not use the
  // existing global refresh endpoint from a customer-specific control.
  await requestCustomerQueryRefresh(companyId,id.slice("query:".length),actor);
  return {queued:true};
}
