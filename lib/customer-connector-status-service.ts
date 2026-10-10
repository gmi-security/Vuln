import { scannerRouteEvidenceSelect, scannerRoutingStatus, type ScannerRouteEvidence } from "./customer-scanner-routing";
import { spotlightRouteEvidenceSelect, spotlightRoutingStatus, type SpotlightRouteEvidence } from "./customer-spotlight-routing";
import { Pool } from "pg";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { buildConnectorPreview, type ConnectorMetadata } from "./customer-connector-preview";
import { customerConnectorStatus, type ConnectorStatusDraft } from "./customer-connector-status";
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from "./db/connector-metadata.mjs";
import { inventoryRouteEvidenceSelect, inventoryRoutingStatus, type InventoryRouteEvidence } from "./customer-inventory-routing";

let dedicated: { url: string; pool: Pool } | undefined;
// Reuse the application pool without schema initialization; keep the optional
// dashboard pool bounded and separate from dashboardDatabase's write hooks.
function dashboardPool(app: Pool) {
  const url = process.env.ELASTIC_VULN_DATABASE_URL;
  if (!url || url === process.env.DATABASE_URL) return app;
  if (!dedicated || dedicated.url !== url) {
    void dedicated?.pool.end().catch(() => {});
    const pool = new Pool({ connectionString: url, max: 1, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000, statement_timeout: 15000 });
    const entry = { url, pool }; dedicated = entry;
    pool.on("error", () => { if (dedicated === entry) dedicated = undefined; void pool.end().catch(() => {}); });
  }
  return dedicated.pool;
}
export async function readCustomerConnectorStatus(companyId: string | null) {
  if (companyId !== null && (!companyId || companyId.length > 100)) throw new DashboardError("Choose an existing customer.", 400);
  const app = applicationDatabase();
  if (!app) throw new DashboardError("Connector metadata storage is unavailable.", 503);
  const client = await app.connect();
  try {
    const application: Pick<ConnectorMetadata, "companies" | "defender" | "spotlight"> = await readApplicationConnectorMetadata(client);
    const companies = application.companies.filter(c => !c.isDemo).map(c => ({ id: c.id, name: c.name }));
    if (companyId === null) return { companies };
    if (!companies.some(c => c.id === companyId)) throw new DashboardError("Customer not found.", 404);
    const dashboard = dashboardPool(app);
    const sourceClient = dashboard === app ? client : await dashboard.connect();
    let saved;
    try { saved = await readDashboardConnectorMetadata(sourceClient); }
    finally { if (sourceClient !== client) sourceClient.release(); }
    const preview = buildConnectorPreview({ ...application, ...saved }, process.env);
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      await client.query("SET LOCAL statement_timeout='15s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      const available = Boolean((await client.query("SELECT to_regclass('public.customer_connector_drafts') AS name")).rows[0].name);
      const drafts: ConnectorStatusDraft[] = available ? (await client.query(`SELECT id,candidate,candidate_hash,proposal,source_present,review_state,reviewed_at
        FROM public.customer_connector_drafts WHERE proposal->>'companyId'=$1 ORDER BY id LIMIT 1001`, [companyId])).rows : [];
      if (drafts.length > 1000) throw new DashboardError("Too many connector proposals to display. Refine the registry review.", 503);
      const bindingsAvailable = Boolean((await client.query("SELECT to_regclass('public.customer_connector_bindings') AS name")).rows[0].name);
      const bindings: ConnectorStatusDraft[] = bindingsAvailable ? (await client.query(`SELECT d.id,d.candidate,b.candidate_hash,b.proposal,
        d.source_present,b.review_state,b.reviewed_at FROM public.customer_connector_bindings b
        JOIN public.customer_connector_drafts d ON d.id=b.candidate_id WHERE b.company_id=$1 ORDER BY d.id LIMIT 1001`,[companyId])).rows : [];
      if (bindings.length > 1000) throw new DashboardError("Too many customer bindings to display.",503);
      // A scoped binding overrides the legacy single proposal for this customer
      // only. Other customers' assignments never enter this projection.
      const scoped = new Map(drafts.map(row => [row.id,row]));
      for (const binding of bindings) scoped.set(binding.id,binding);
      const routingAvailable = Boolean((await client.query("SELECT to_regclass('public.customer_inventory_routes') AS name")).rows[0].name);
      const routes: InventoryRouteEvidence[] = routingAvailable ? (await client.query(`${inventoryRouteEvidenceSelect}
        WHERE r.company_id=$1 ORDER BY r.candidate_id LIMIT 1001`,[companyId])).rows : [];
      if (routes.length > 1000) throw new DashboardError("Too many inventory routes to display.",503);
      const spotlightAvailable = Boolean((await client.query("SELECT to_regclass('public.customer_spotlight_routes') AS name")).rows[0].name);
      const spotlight: SpotlightRouteEvidence[] = spotlightAvailable ? (await client.query(`${spotlightRouteEvidenceSelect}
        WHERE r.company_id=$1 ORDER BY r.candidate_id LIMIT 1001`,[companyId])).rows : [];
      if (spotlight.length > 1000) throw new DashboardError("Too many Spotlight routes to display.",503);
      const scannerAvailable = Boolean((await client.query("SELECT to_regclass('public.customer_scanner_routes') AS name")).rows[0].name);
      const scanner: ScannerRouteEvidence[] = scannerAvailable ? (await client.query(`${scannerRouteEvidenceSelect}
        WHERE r.company_id=$1 ORDER BY r.candidate_id LIMIT 1001`,[companyId])).rows : [];
      if (scanner.length > 1000) throw new DashboardError("Too many scanner routes to display.",503);
      const result = customerConnectorStatus(companyId, preview, [...scoped.values()], available, undefined,
        routes.map(row=>inventoryRoutingStatus(row,preview,process.env.VULN_REVIEWED_INVENTORY_PROVIDERS)),
        spotlight.map(row=>spotlightRoutingStatus(row,preview,process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS)),
        scanner.map(row=>scannerRoutingStatus(row,preview,process.env.VULN_REVIEWED_SCANNER_PROVIDERS)));
      await client.query("COMMIT");
      return result;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
  } finally { client.release(); }
}
