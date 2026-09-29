import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { triggerAbandonAndReplaceNow } from "@/lib/group-ticket-reconciliation";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(triggerAbandonAndReplaceNow());
  } catch (error) { return dashboardFailure(error); }
}
