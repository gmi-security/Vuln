import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { reorderDashboardTiles } from "@/lib/elastic-dashboard-store";

export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    const { actor } = await dashboardAccess(request, true);
    await reorderDashboardTiles(await dashboardBody(request), actor);
    return dashboardJson({ saved: true });
  } catch (error) { return dashboardFailure(error); }
}
