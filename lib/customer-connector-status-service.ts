import { Pool } from "pg";
import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { buildConnectorPreview, type ConnectorMetadata } from "./customer-connector-preview";
import { customerConnectorStatus, type ConnectorStatusDraft } from "./customer-connector-status";
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from "./db/connector-metadata.mjs";

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
      const result = customerConnectorStatus(companyId, preview, drafts, available);
      await client.query("COMMIT");
      return result;
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
  } finally { client.release(); }
}
