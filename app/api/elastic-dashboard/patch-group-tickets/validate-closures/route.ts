import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { syncAndValidateClosedGroupTickets } from "@/lib/group-closure-validation";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(await syncAndValidateClosedGroupTickets());
  } catch (error) { return dashboardFailure(error); }
}
