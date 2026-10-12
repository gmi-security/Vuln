import {dashboardAccess,dashboardFailure,dashboardJson} from "@/lib/elastic-dashboard-http";
import {DashboardError} from "@/lib/elastic-dashboard";
import {remediationUiEnabled} from "@/lib/remediation-server";
import {readShadowPlatformPreview} from "@/lib/shadow-platform-preview";
export const dynamic="force-dynamic";
export async function GET(request:Request){
  try{
    await dashboardAccess();
    if(!remediationUiEnabled()||process.env.VULN_SHADOW_CVE_READS!=="true")throw new DashboardError("Not found",404);
    const params=new URL(request.url).searchParams;
    if(params.getAll("companyId").length!==1||[...params.keys()].some(key=>
      !["companyId","view","status","limit","cursor"].includes(key)||params.getAll(key).length!==1))throw new DashboardError("Choose one customer and comparison view.",400);
    return dashboardJson(await readShadowPlatformPreview(Object.fromEntries(params)));
  }catch(error){return dashboardFailure(error);}
}
