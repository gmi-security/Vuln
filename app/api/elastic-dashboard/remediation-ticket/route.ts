import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { prepareRemediationTicket } from "@/lib/remediation-ticket-service";
export const dynamic="force-dynamic";
export async function POST(request:Request) {
  try {
    const {actor}=await dashboardAccess(request,true);
    if(!remediationUiEnabled())throw new DashboardError("Not found",404);
    const body=await dashboardBody(request) as {companyId?:string;id?:unknown};
    return dashboardJson(await prepareRemediationTicket(body?.companyId ?? "",body?.id,actor));
  }catch(error){return dashboardFailure(error);}
}
