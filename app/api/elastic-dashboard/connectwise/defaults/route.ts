import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { saveCWDefaults } from "@/lib/patch-ticket-store";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try { const { actor } = await dashboardAccess(request, true); return dashboardJson(await saveCWDefaults(await dashboardBody(request), actor)); } catch (error) { return dashboardFailure(error); }
}
