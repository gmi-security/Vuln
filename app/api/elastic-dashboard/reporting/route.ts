import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { reportingCustomer, reportingOverview, reportingSetup } from "@/lib/reporting-store";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    const companyId = params.get("companyId"), view = params.get("view");
    if (view !== null && (view !== "sections" || !companyId)) throw new DashboardError("Choose a customer and valid report view.", 400);
    if (view === "sections") return dashboardJson(await reportingOverview(companyId!));
    return dashboardJson(companyId === null ? await reportingSetup() : await reportingCustomer(companyId));
  } catch (error) { return dashboardFailure(error); }
}
