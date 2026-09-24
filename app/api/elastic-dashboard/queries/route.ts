import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { enqueueDashboardJob } from "@/lib/elastic-dashboard-jobs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    const { actor } = await dashboardAccess(request, true);
    return dashboardJson(await enqueueDashboardJob("save", await dashboardBody(request), actor), 202);
  } catch (error) { return dashboardFailure(error); }
}
