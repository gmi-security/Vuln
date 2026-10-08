import { DashboardError } from "@/lib/elastic-dashboard";
import { assignDashboardTile } from "@/lib/elastic-dashboard-store";
import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
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
    if (request.headers.get("content-type")?.startsWith("application/json")) {
      const body = await dashboardBody(request) as {action?:string;id?:string};
      if (body?.action !== undefined) {
        if (body.action !== "assign" || typeof body.id !== "string") throw new DashboardError("Choose an existing tile to attach.");
        return dashboardJson(await assignDashboardTile(body.id,companyId,access.actor));
      }
    }
    return dashboardJson(await refreshCustomerTiles(companyId,access.canManage),202);
  } catch (error) { return dashboardFailure(error); }
}
