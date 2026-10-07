import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readCustomerTiles, refreshCustomerTiles } from "@/lib/reporting-customer-tiles";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const access = await dashboardAccess();
    const companyId = new URL(request.url).searchParams.get("companyId") ?? "";
    return dashboardJson(await readCustomerTiles(companyId,access.canManage));
  } catch (error) { return dashboardFailure(error); }
}

export async function POST(request: Request) {
  try {
    const access = await dashboardAccess(request,true);
    const companyId = new URL(request.url).searchParams.get("companyId") ?? "";
    return dashboardJson(await refreshCustomerTiles(companyId,access.canManage),202);
  } catch (error) { return dashboardFailure(error); }
}
