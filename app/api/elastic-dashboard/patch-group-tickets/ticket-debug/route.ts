import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { patchTicketDatabase, savedConnection } from "@/lib/patch-ticket-store";
import { DashboardError } from "@/lib/elastic-dashboard";
export const dynamic = "force-dynamic";

// Temporary, read-only diagnostic: shows exactly what's stored for a given
// ConnectWise ticket number in both tables, and the ConnectWise target this
// connection currently resolves to -- so a "not found" from findTrackedRow
// can be explained by an actual stored value instead of guessed at.
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const ticketId = Number(new URL(request.url).searchParams.get("ticketId"));
    if (!Number.isSafeInteger(ticketId) || ticketId <= 0) throw new DashboardError("Choose a valid ticket number.", 400);
    const db = await patchTicketDatabase();
    const saved = await savedConnection().catch(() => null);
    const [group, single] = await Promise.all([
      db.query("SELECT id, state, cw_target, ticket_id, closed, routing FROM patch_group_ticket_requests WHERE ticket_id=$1", [ticketId]),
      db.query("SELECT id, state, cw_target, ticket_id, closed, routing FROM patch_ticket_requests WHERE ticket_id=$1", [ticketId]),
    ]);
    return dashboardJson({
      currentTarget: saved?.target ?? null,
      group: group.rows,
      single: single.rows,
    });
  } catch (error) { return dashboardFailure(error); }
}
