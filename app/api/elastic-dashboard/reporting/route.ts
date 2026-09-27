import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { linkReportingCompany, reportingCustomer, reportingLinkForAppCompany, reportingSetup } from "@/lib/reporting-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    if (params.has("appCompanyId")) return dashboardJson(await reportingLinkForAppCompany(params.get("appCompanyId") ?? ""));
    const value = params.get("cwCompanyId");
    if (value === null) return dashboardJson(await reportingSetup());
    return dashboardJson(await reportingCustomer(Number(value)));
  } catch (error) { return dashboardFailure(error); }
}

export async function PUT(request: Request) {
  try {
    const access = await dashboardAccess(request, true);
    const body = await dashboardBody(request) as { cwCompanyId?: unknown; appCompanyId?: unknown };
    return dashboardJson(await linkReportingCompany(Number(body?.cwCompanyId), body?.appCompanyId as string, access.actor));
  } catch (error) { return dashboardFailure(error); }
}
