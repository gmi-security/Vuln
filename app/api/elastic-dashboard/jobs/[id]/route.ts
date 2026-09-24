import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readDashboardJob } from "@/lib/elastic-dashboard-jobs";
export const dynamic = "force-dynamic";
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const { actor } = await dashboardAccess();
    return dashboardJson(await readDashboardJob((await context.params).id, actor));
  } catch (error) { return dashboardFailure(error); }
}
