import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readCustomerTopFixes } from "@/lib/customer-top-fixes";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    return dashboardJson(await readCustomerTopFixes(new URL(request.url).searchParams.get("companyId")));
  } catch (error) { return dashboardFailure(error); }
}
