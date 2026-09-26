import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readCWSettings, saveCWSettings } from "@/lib/patch-ticket-store";
export const dynamic = "force-dynamic";
export async function GET() {
  try { await dashboardAccess(); return dashboardJson(await readCWSettings()); } catch (error) { return dashboardFailure(error); }
}
export async function POST(request: Request) {
  try { const { actor } = await dashboardAccess(request, true); return dashboardJson(await saveCWSettings(await dashboardBody(request), actor)); } catch (error) { return dashboardFailure(error); }
}
