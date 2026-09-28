import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readDashboard } from "@/lib/elastic-dashboard-store";
import { directSourcesForCustomer, emptyReportingDashboard, hasDirectReportingSources } from "@/lib/reporting-direct-sources";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const access = await dashboardAccess();
    const companyId = new URL(request.url).searchParams.get("companyId") ?? "";
    if (!hasDirectReportingSources(companyId)) return dashboardJson(emptyReportingDashboard(access.canManage));
    return dashboardJson(directSourcesForCustomer(companyId, await readDashboard(access.canManage), process.env.ATLAS_REPORTING_TILE_IDS));
  } catch (error) { return dashboardFailure(error); }
}
