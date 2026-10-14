import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { customerThreatIntelligence } from "@/lib/customer-threat-intelligence";
export const dynamic="force-dynamic";
export async function GET(request:Request){
  try {await dashboardAccess();if(!remediationUiEnabled())throw new DashboardError("Not found",404);
    return dashboardJson(await customerThreatIntelligence(new URL(request.url).searchParams.get("companyId") ?? ""));
  } catch(error){return dashboardFailure(error);}
}
