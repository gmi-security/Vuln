import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { reportingCustomer, reportingSetup } from "@/lib/reporting-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const companyId = new URL(request.url).searchParams.get("companyId");
    return dashboardJson(companyId === null ? await reportingSetup() : await reportingCustomer(companyId));
  } catch (error) { return dashboardFailure(error); }
}
