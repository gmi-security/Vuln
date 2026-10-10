import type { Pool } from "pg";
import { applicationDatabase } from "./persist";
import { createQueryRoutingStore, reviewedQueryRouting, type QueryRoute } from "./customer-query-routing";
import { DashboardError } from "./elastic-dashboard";

export async function loadReviewedQueryRoutes(dashboard: Pick<Pool, "connect">): Promise<QueryRoute[] | null> {
  const env = { ...process.env };
  if (!reviewedQueryRouting(env.VULN_REVIEWED_QUERY_PROVIDERS)) return null;
  const app = applicationDatabase();
  if (!app) throw new DashboardError("Customer query routing storage is unavailable.", 503);
  try {
    const { readApplicationConnectorMetadata, readDashboardConnectorMetadata } = await import("./db/connector-metadata.mjs");
    const { buildConnectorPreview } = await import("./customer-connector-preview");
    // Collect before opening the route transaction: dashboard and application
    // pools may be the same bounded pool. Never reserve a connection while
    // waiting for nested metadata reads from that pool.
    const a = await app.connect();
    let metadata;
    try { metadata = await readApplicationConnectorMetadata(a); } finally { a.release(); }
    const d = await dashboard.connect();
    let saved;
    try { saved = await readDashboardConnectorMetadata(d); } finally { d.release(); }
    const preview = buildConnectorPreview({ ...metadata, ...saved, tiles: [] }, env);
    return await createQueryRoutingStore(app).read("crowdstrike", async () => preview);
  } catch { throw new DashboardError("Customer query routing needs renewed approval. No shared unscoped query was used.", 503); }
}
export function selectQueryRoute(routes: QueryRoute[] | null, companyId?: string | null, cid?: string, revision?: number): QueryRoute | null {
  if (routes === null) return null;
  // Legacy ticket verification can identify an existing owner by its exact CID.
  const matches = routes.filter(r => companyId ? r.companyId === companyId : cid ? r.sourceScope === cid.toLowerCase() : false);
  if (matches.length !== 1 || (cid && matches[0].sourceScope !== cid.toLowerCase()) ||
      (revision !== undefined && matches[0].connectionRevision !== revision))
    throw new DashboardError("Choose a customer with a current approved CrowdStrike query connection and matching CID.", 409);
  return matches[0];
}
export async function recheckQueryRoute(dashboard: Pick<Pool, "connect">, expected: QueryRoute | null) {
  if (!expected) return;
  const current = selectQueryRoute(await loadReviewedQueryRoutes(dashboard), expected.companyId, expected.sourceScope, expected.connectionRevision);
  if (!current || current.bindingKey !== expected.bindingKey) throw new DashboardError("Customer query approval changed during collection. Results were withheld.", 409);
}
