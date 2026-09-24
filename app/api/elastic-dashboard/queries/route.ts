import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { addDashboardTile } from "@/lib/elastic-dashboard-store";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    const { actor } = await dashboardAccess(request, true);
    return dashboardJson(await addDashboardTile(await dashboardBody(request), actor), 201);
  } catch (error) { return dashboardFailure(error); }
}
