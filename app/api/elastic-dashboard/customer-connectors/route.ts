import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { readCustomerConnectorStatus } from "@/lib/customer-connector-status-service";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    if (!remediationUiEnabled()) throw new DashboardError("Not found", 404);
    const params = new URL(request.url).searchParams;
    if (params.get("setup") === "1" && !params.has("companyId")) return dashboardJson(await readCustomerConnectorStatus(null));
    const companyId = params.get("companyId");
    if (!companyId) throw new DashboardError("Choose an existing customer.", 400);
    return dashboardJson(await readCustomerConnectorStatus(companyId));
  } catch (error) { return dashboardFailure(error); }
}
