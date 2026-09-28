import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { validateClosedGroupTickets } from "@/lib/group-closure-validation";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(await validateClosedGroupTickets());
  } catch (error) { return dashboardFailure(error); }
}
