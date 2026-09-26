import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { listPatchTickets } from "@/lib/patch-ticket-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try { await dashboardAccess(); return dashboardJson(await listPatchTickets(new URL(request.url).searchParams.get("cve") ?? undefined)); } catch (error) { return dashboardFailure(error); }
}
