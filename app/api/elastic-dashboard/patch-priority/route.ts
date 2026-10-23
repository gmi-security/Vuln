import {dashboardAccess,dashboardFailure,dashboardJson} from "@/lib/elastic-dashboard-http";
import {dashboardReadDatabase} from "@/lib/elastic-dashboard-store";
import {customerPatchPriority} from "@/lib/customer-patch-priority";
export const dynamic="force-dynamic";
export async function GET(request:Request){try{await dashboardAccess();return dashboardJson(await customerPatchPriority(new URL(request.url).searchParams.get("companyId"),dashboardReadDatabase,request.signal));}catch(error){return dashboardFailure(error);}}
