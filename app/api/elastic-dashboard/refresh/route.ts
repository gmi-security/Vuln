import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { triggerRefresh } from "@/lib/elastic-dashboard-store";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    triggerRefresh(true);
    return dashboardJson({ queued: true }, 202);
  } catch (error) { return dashboardFailure(error); }
}
