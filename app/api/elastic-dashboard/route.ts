import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readDashboard, triggerRefresh } from "@/lib/elastic-dashboard-store";
export const dynamic = "force-dynamic";
export async function GET() {
  try {
    const access = await dashboardAccess();
    triggerRefresh();
    return dashboardJson(await readDashboard(access.canManage));
  } catch (error) { return dashboardFailure(error); }
}
