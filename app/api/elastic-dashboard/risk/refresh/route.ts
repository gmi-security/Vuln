import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { triggerRiskRefreshNow } from "@/lib/risk-refresh-scheduler";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(triggerRiskRefreshNow());
  } catch (error) { return dashboardFailure(error); }
}
