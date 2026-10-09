import { DashboardError } from "./elastic-dashboard";
import { readDashboard, triggerRefresh } from "./elastic-dashboard-store";
import { customerReportingTileIds, directSourcesForCustomer, emptyReportingDashboard } from "./reporting-direct-sources";
import { resolveCustomerScope } from "./customer-scope";

export async function readCustomerTiles(companyId: string, canManage: boolean) {
  if (!companyId) return emptyReportingDashboard(canManage);
  await resolveCustomerScope(companyId);
  const configured = process.env.REPORTING_CUSTOMER_TILE_IDS ?? "", atlasIds = process.env.ATLAS_REPORTING_TILE_IDS ?? "";
  try {
    customerReportingTileIds(companyId,configured,atlasIds);
    return directSourcesForCustomer(companyId,await readDashboard(canManage,companyId),atlasIds,configured);
  } catch (error) {
    if (error instanceof DashboardError) throw error;
    throw new DashboardError("Customer tile assignments need to be checked in the server configuration.",503);
  }
}

export async function refreshCustomerTiles(companyId: string, canManage: boolean) {
  if (!companyId) throw new DashboardError("Choose a customer before refreshing.",400);
  const dashboard = await readCustomerTiles(companyId,canManage);
  if (!dashboard.storageReady) throw new DashboardError("Dashboard storage is unavailable.",503);
  const ids = dashboard.queries.map(query=>query.id);
  if (ids.length) triggerRefresh(true,ids);
  return { queued:ids.length > 0, count:ids.length };
}
