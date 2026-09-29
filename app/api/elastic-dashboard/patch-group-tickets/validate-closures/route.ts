import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { triggerClosureValidationNow } from "@/lib/group-closure-validation";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson(triggerClosureValidationNow());
  } catch (error) { return dashboardFailure(error); }
}
