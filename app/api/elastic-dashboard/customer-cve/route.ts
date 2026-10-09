import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { remediationUiEnabled } from "@/lib/remediation-server";
import { prepareCustomerCve, readCustomerCve } from "@/lib/customer-cve-service";
export const dynamic="force-dynamic";
function enabled(){if(!remediationUiEnabled())throw new DashboardError("Not found",404);}
export async function GET(request:Request){
  try {await dashboardAccess();enabled();const params=new URL(request.url).searchParams;
    return dashboardJson(await readCustomerCve(params.get("companyId") ?? "",params.get("cve")));
  } catch(error){return dashboardFailure(error);}
}
export async function POST(request:Request){
  try {const {actor}=await dashboardAccess(request,true);enabled();
    const body=await dashboardBody(request) as {companyId?:string;cve?:string};
    return dashboardJson(await prepareCustomerCve(body?.companyId ?? "",body?.cve,actor));
  } catch(error){return dashboardFailure(error);}
}
