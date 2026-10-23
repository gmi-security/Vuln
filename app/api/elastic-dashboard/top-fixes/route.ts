import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readCustomerTopFixes } from "@/lib/customer-top-fixes";
import { dashboardReadDatabase } from "@/lib/elastic-dashboard-store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    return dashboardJson(await readCustomerTopFixes(new URL(request.url).searchParams.get("companyId"),dashboardReadDatabase,false,request.signal));
  } catch (error) { return dashboardFailure(error); }
}
