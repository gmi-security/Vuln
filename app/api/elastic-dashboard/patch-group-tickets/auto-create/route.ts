import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { autoCreateHighSeverityTickets } from "@/lib/group-auto-create";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(await autoCreateHighSeverityTickets());
  } catch (error) { return dashboardFailure(error); }
}
