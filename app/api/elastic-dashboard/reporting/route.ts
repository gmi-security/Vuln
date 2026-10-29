import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { reportingCustomer, reportingOverview, reportingSetup } from "@/lib/reporting-store";
import { DashboardError } from "@/lib/elastic-dashboard";
import { reportingCrowdstrike } from "@/lib/reporting-crowdstrike";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    const companyId = params.get("companyId"), view = params.get("view");
    if (view !== null && (view !== "sections" || !companyId)) throw new DashboardError("Choose a customer and valid report view.", 400);
    if (companyId === null) return dashboardJson(await reportingSetup());
    const report = view === "sections" ? await reportingOverview(companyId) : await reportingCustomer(companyId);
    const crowdstrikeReport = await reportingCrowdstrike(report.model.company.id);
    return dashboardJson({ ...report, model: { ...report.model, crowdstrikeReport } });
  } catch (error) { return dashboardFailure(error); }
}
