import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { readCustomerSyncStatus, startCustomerSync } from "@/lib/customer-connector-sync-service";
export const dynamic = "force-dynamic";
function company(request: Request) {
  if (!remediationUiEnabled()) throw new DashboardError("Not found",404);
  const id = new URL(request.url).searchParams.get("companyId");
  if (!id?.trim() || id.length > 100) throw new DashboardError("Choose an existing customer.");
  return id;
}
export async function GET(request: Request) {
  try { await dashboardAccess(); return dashboardJson(await readCustomerSyncStatus(company(request))); }
  catch(error) { return dashboardFailure(error); }
}
export async function POST(request: Request) {
  try {
    const { actor } = await dashboardAccess(request,true), companyId = company(request);
    const body = await dashboardBody(request,1024) as { id?: unknown };
    if (!body || typeof body.id !== "string" || body.id.length > 100 || Object.keys(body).some(key=>key!=="id"))
      throw new DashboardError("Choose one connector sync action.");
    return dashboardJson(await startCustomerSync(companyId,body.id,actor),202);
  } catch(error) { return dashboardFailure(error); }
}
