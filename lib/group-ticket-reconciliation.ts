import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { cwRequest, cwId, ticketUrl } from "./connectwise-client";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";

export type UntrackedTicket = { id: number; summary: string; status: string; closed: boolean; url: string };

// Every piece of this pipeline's automation (auto-create, priority backfill,
// closure-validation) can only ever see a ConnectWise ticket if it exists as
// a row in patch_group_ticket_requests with that ticket's real id attached.
// A ticket created by pasting draft text directly into ConnectWise instead
// of through the app's own "Create ticket" action has no such row, and is
// invisible to all of it, no matter what gets built next. This is a
// read-only diff against the live ConnectWise board: every current Atlas
// ticket that isn't backed by a tracked row, so it can be handled by hand
// instead of discovered one ticket at a time.
export async function findUntrackedAtlasTickets(): Promise<UntrackedTicket[]> {
  const saved = await savedConnection();
  const db = await patchTicketDatabase();
  const routing = (await db.query("SELECT company_id FROM patch_customer_routing WHERE app_company_id=$1", [ATLAS_REPORTING_COMPANY_ID]))
    .rows[0] as { company_id: number } | undefined;
  if (!routing) return [];
  const trackedRows = (await db.query("SELECT ticket_id FROM patch_group_ticket_requests WHERE ticket_id IS NOT NULL AND cw_target=$1", [saved.target]))
    .rows as { ticket_id: number }[];
  const tracked = new Set(trackedRows.map((r) => r.ticket_id));
  const untracked: UntrackedTicket[] = [];
  for (let page = 1; page <= 20; page++) {
    const rows = await cwRequest(saved.value, `/service/tickets?${new URLSearchParams({
      conditions: `company/id=${routing.company_id}`, pageSize: "100", page: String(page),
    })}`);
    if (!Array.isArray(rows) || !rows.length) break;
    for (const row of rows) {
      if (!cwId(row.id) || tracked.has(row.id)) continue;
      untracked.push({
        id: row.id,
        summary: typeof row.summary === "string" ? row.summary : "",
        status: typeof row.status?.name === "string" ? row.status.name : "",
        closed: row.closedFlag === true,
        url: ticketUrl(saved.value, row.id),
      });
    }
    if (rows.length < 100) break;
  }
  return untracked;
}
