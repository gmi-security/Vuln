import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { cwRequest, cwId, ticketUrl, type CWRecord, type ConnectWiseConnection } from "./connectwise-client";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";

export type UntrackedTicket = { id: number; summary: string; status: string; closed: boolean; url: string };
const ACTOR = "ticket-reconciliation";

// Shared by findUntrackedAtlasTickets and adoptManualAtlasTickets: every live
// Atlas ticket in ConnectWise (paginated, full raw rows), and the set of
// ticket_ids already tracked by a row in patch_group_ticket_requests for the
// current ConnectWise connection.
async function liveAtlasTickets(): Promise<{ saved: Awaited<ReturnType<typeof savedConnection>>; tracked: Set<number>; rows: CWRecord[] }> {
  const saved = await savedConnection();
  const db = await patchTicketDatabase();
  const routing = (await db.query("SELECT company_id FROM patch_customer_routing WHERE app_company_id=$1", [ATLAS_REPORTING_COMPANY_ID]))
    .rows[0] as { company_id: number } | undefined;
  if (!routing) return { saved, tracked: new Set(), rows: [] };
  const trackedRows = (await db.query("SELECT ticket_id FROM patch_group_ticket_requests WHERE ticket_id IS NOT NULL AND cw_target=$1", [saved.target]))
    .rows as { ticket_id: number }[];
  const tracked = new Set(trackedRows.map((r) => r.ticket_id));
  const rows: CWRecord[] = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await cwRequest(saved.value, `/service/tickets?${new URLSearchParams({
      conditions: `company/id=${routing.company_id}`, pageSize: "100", page: String(page),
    })}`);
    if (!Array.isArray(batch) || !batch.length) break;
    rows.push(...batch);
    if (batch.length < 100) break;
  }
  return { saved, tracked, rows };
}

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
  const { saved, tracked, rows } = await liveAtlasTickets();
  const untracked: UntrackedTicket[] = [];
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
  return untracked;
}

const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

async function draftUuidForTicket(connection: ConnectWiseConnection, ticketId: number): Promise<string | null> {
  const docs = await cwRequest(connection, `/system/documents?${new URLSearchParams({
    recordType: "Ticket", recordId: String(ticketId), pageSize: "10",
  })}`);
  if (!Array.isArray(docs)) return null;
  for (const doc of docs) {
    const match = typeof doc?.title === "string" ? doc.title.match(UUID_PATTERN) : null;
    if (match) return match[0].toLowerCase();
  }
  return null;
}

export type AdoptResult = { checked: number; adopted: number; noMatch: number; errors: number };

// A manually-pasted ticket's draft text came from this app's own prepared
// consolidation, and the CSV attached to it at creation time is named after
// that exact draft's id (a UUID) -- see draftUuidForTicket. That's an exact,
// unambiguous link back to a row in patch_group_ticket_requests, not a
// guess. Adopting it -- filling in ticket_id/routing/state the same way a
// normal creation would have -- makes the ticket visible to every piece of
// automation in this pipeline from then on, including the next
// closure-validation pass, which will attempt to reopen it like any other
// tracked ticket. A draft that's already superseded, dismissed, or already
// linked to a different ticket simply won't match state='prepared' and is
// left alone -- never overwrites an existing tracked row.
export async function adoptManualAtlasTickets(): Promise<AdoptResult> {
  const { saved, tracked, rows } = await liveAtlasTickets();
  const db = await patchTicketDatabase();
  let adopted = 0, noMatch = 0, errors = 0, checked = 0;
  for (const row of rows) {
    if (!cwId(row.id) || tracked.has(row.id)) continue;
    checked++;
    try {
      const uuid = await draftUuidForTicket(saved.value, row.id);
      if (!uuid) { noMatch++; continue; }
      const draft = (await db.query("SELECT id FROM patch_group_ticket_requests WHERE id=$1 AND state='prepared'", [uuid])).rows[0];
      if (!draft) { noMatch++; continue; }
      const boardId = row.board?.id, companyId = row.company?.id;
      if (!cwId(boardId) || !cwId(companyId)) { noMatch++; continue; }
      const routing = { companyId, boardId };
      await db.query(`UPDATE patch_group_ticket_requests SET state='created',ticket_id=$2,ticket_url=$3,ticket_status=$4,closed=$5,
        cw_target=$6,cw_revision=$7,company_id=$8,routing=$9::jsonb,attachment_state='attached',created_by=$10,started_at=now(),updated_at=now(),last_error=NULL
        WHERE id=$1 AND ticket_id IS NULL`,
        [uuid, row.id, ticketUrl(saved.value, row.id), typeof row.status?.name === "string" ? row.status.name : "Unknown",
          row.closedFlag === true, saved.target, saved.revision, companyId, JSON.stringify(routing), ACTOR]);
      await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.adopted')", [uuid, ACTOR]);
      adopted++;
    } catch {
      errors++; // one ticket's lookup failing must not block the rest
    }
  }
  return { checked, adopted, noMatch, errors };
}
