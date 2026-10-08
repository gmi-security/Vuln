import { DashboardError } from "./elastic-dashboard";
import { readDashboard, triggerRefresh } from "./elastic-dashboard-store";
import { customerReportingTileIds, directSourcesForCustomer, emptyReportingDashboard } from "./reporting-direct-sources";
import { ensureHydrated, getCompany } from "./store";

export async function readCustomerTiles(companyId: string, canManage: boolean) {
  if (!companyId) return emptyReportingDashboard(canManage);
  if (companyId.length > 100) throw new DashboardError("Choose an existing customer.",400);
  await ensureHydrated();
  const company = getCompany(companyId);
  if (!company || company.isDemo) throw new DashboardError("Customer not found.",404);
  const configured = process.env.REPORTING_CUSTOMER_TILE_IDS ?? "", atlasIds = process.env.ATLAS_REPORTING_TILE_IDS ?? "";
  try {
    if (!customerReportingTileIds(companyId,configured,atlasIds).length) return emptyReportingDashboard(canManage);
    return directSourcesForCustomer(companyId,await readDashboard(canManage),atlasIds,configured);
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
