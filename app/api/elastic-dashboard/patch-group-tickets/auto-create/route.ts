import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    return dashboardJson({ error: "Automatic ticket creation has been removed. Prepare a draft from a CVE, then review and approve it on the Tickets page before sending to ConnectWise." }, 410);
  } catch (error) { return dashboardFailure(error); }
}
