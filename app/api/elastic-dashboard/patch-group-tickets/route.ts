import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { listGroupTickets } from "@/lib/patch-group-ticket-store";
export const dynamic = "force-dynamic";
export async function GET() {
  try { await dashboardAccess(); return dashboardJson(await listGroupTickets()); } catch (error) { return dashboardFailure(error); }
}
