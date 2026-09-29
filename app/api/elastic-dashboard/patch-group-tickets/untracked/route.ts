import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { findUntrackedAtlasTickets } from "@/lib/group-ticket-reconciliation";
export const dynamic = "force-dynamic";
export async function GET() {
  try {
    await dashboardAccess();
    return dashboardJson({ tickets: await findUntrackedAtlasTickets() });
  } catch (error) { return dashboardFailure(error); }
}
