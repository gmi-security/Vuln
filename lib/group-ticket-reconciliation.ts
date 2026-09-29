import { randomUUID } from "node:crypto";
import { patchTicketDatabase, savedConnection, activeTicketedPairs, persistPreparedPatch } from "./patch-ticket-store";
import { persistPreparedGroups } from "./patch-group-ticket-store";
import { dashboardConnectionRevision, prepareConsolidation, preparePatchRequest } from "./elastic-dashboard-store";
import { cwRequest, cwId, ticketUrl, type CWRecord, type ConnectWiseConnection } from "./connectwise-client";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { DashboardError } from "./elastic-dashboard";
import type { PatchGroup } from "./patch-request";

export type UntrackedTicket = { id: number; summary: string; status: string; closed: boolean; url: string };
const ACTOR = "ticket-reconciliation";

// The 37 tickets absorbed into parent #2655137's Combine and closed on 9/28
// before patching happened -- read directly off that parent's own "Combined
// Tickets: 37" list and its 37 UUID-tagged CSV attachments (see #2655137 in
// ConnectWise). #2655138 was originally left out (created the same minute as
// the parent, 9/26, looked like the original rollout rather than the later
// manual-paste incident) -- confirmed 9/29 it's the same story: still closed,
// still untracked, 1285 devices with no fix behind it, so it's included.
// abandonAndReplaceUntrackedAtlasTickets only ever writes to a ticket number
// in this list -- a hard ceiling on top of the closed/untracked/patch-board
// filters, not a replacement for them, so a future unrelated closed/untracked
// ticket can never be swept in by this same action without a deliberate code change.
const KNOWN_LOST_ATLAS_TICKET_IDS = new Set([
  2655138, 2655148, 2655170, 2655171, 2655172, 2655173, 2655174, 2655175,
  2655990, 2655991, 2655996, 2656104, 2656130,
  2656151, 2656152, 2656153, 2656154, 2656155, 2656156, 2656157, 2656158, 2656159,
  2656160, 2656161, 2656162, 2656163, 2656164, 2656165, 2656166, 2656167, 2656168, 2656169,
  2656170, 2656171, 2656172, 2656173, 2656174,
]);

// Shared by findUntrackedAtlasTickets and adoptManualAtlasTickets: every live
// Atlas *patch* ticket in ConnectWise (paginated, full raw rows), and the set
// of ticket_ids already tracked by a row in EITHER ticket table for the
// current ConnectWise connection -- the group-consolidation table this file
// otherwise deals in, and the single-CVE table (patch_ticket_requests), whose
// own tickets use the same "Patch "-prefixed board and can just as easily be
// pasted in by hand. #2655137 is a real example: its body is the single-CVE
// draft template, not the group one, so it's tracked over there -- checking
// only the group table would wrongly call an already-tracked ticket
// "untracked." Scoped to the Atlas patch board and to ticket summaries
// containing "Patch " -- every ticket this app has ever produced (auto-
// created or a manually-pasted draft, from either flow) starts its title
// with exactly that (see ticketTitle in patch-request.ts and buildPatchRequest's
// own title). Without both filters this pulls every ticket ever opened for
// the company across every board -- sales quotes, HR requests, monitoring
// alerts, hardware orders -- which is not what "untracked Atlas ticket" means here.
async function liveAtlasTickets(): Promise<{ saved: Awaited<ReturnType<typeof savedConnection>>; tracked: Set<number>; rows: CWRecord[] }> {
  const saved = await savedConnection();
  const db = await patchTicketDatabase();
  const routing = (await db.query("SELECT company_id, board_id FROM patch_customer_routing WHERE app_company_id=$1", [ATLAS_REPORTING_COMPANY_ID]))
    .rows[0] as { company_id: number; board_id: number } | undefined;
  if (!routing) return { saved, tracked: new Set(), rows: [] };
  const [groupTracked, singleTracked] = await Promise.all([
    db.query("SELECT ticket_id FROM patch_group_ticket_requests WHERE ticket_id IS NOT NULL AND cw_target=$1", [saved.target]),
    db.query("SELECT ticket_id FROM patch_ticket_requests WHERE ticket_id IS NOT NULL AND cw_target=$1", [saved.target]),
  ]);
  const tracked = new Set([...groupTracked.rows, ...singleTracked.rows].map((r) => (r as { ticket_id: number }).ticket_id));
  const rows: CWRecord[] = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await cwRequest(saved.value, `/service/tickets?${new URLSearchParams({
      conditions: `company/id=${routing.company_id} AND board/id=${routing.board_id} AND summary contains "Patch "`,
      pageSize: "100", page: String(page),
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

export type AbandonResult = { checked: number; abandoned: number; cvesReplaced: number; cvesNeedsReview: number; cvesAlreadyCovered: number; unresolved: number; errors: number };
// buildPatchRequest/buildPatchConsolidation raise exactly this shape of
// DashboardError when a fresh CrowdStrike collection finds nothing left to
// act on -- either no open findings at all (already patched since the
// original ticket was cut) or every finding already sits under a different
// active ticket. Both are a correct, unsurprising "nothing to replace"
// outcome, not a failure, so they're counted separately from real errors
// (auth/network/connection-revision failures) instead of hiding either one
// inside a generic error count.
function isNothingLeftToReplace(error: unknown): boolean {
  return error instanceof DashboardError && /no open\/reopened findings|already has an active ticket in progress/i.test(error.message);
}

// For a ticket that's untracked *and* already closed (a ticket adoption
// couldn't link to a still-pending draft, or a human never intends to work
// it as-is -- e.g. one of the 37 Combined Tickets closed before patching
// happened), there is no ticket to reopen or reconsolidate. This writes it
// off instead: the originating draft (found the same way adoption finds
// it, via the attachment's UUID) is marked abandoned with a permanent
// record of why, and every CVE it covered is queued for a brand new
// consolidation -- using the same live CrowdStrike collection and the same
// already-ticketed exclusion (activeTicketedPairs) every other ticket in
// this app goes through, so a CVE that's already covered by a different,
// still-open tracked ticket (the parent it may have been merged into)
// never gets a duplicate. Two or more CVEs land in a normal group draft,
// which the existing auto-create pass turns into a real ticket on its own;
// a single leftover CVE has no group auto-create path, so it's left as a
// single-CVE draft for a human to finish. A ticket with no resolvable
// origin is left completely untouched, same as adoptManualAtlasTickets.
export async function abandonAndReplaceUntrackedAtlasTickets(): Promise<AbandonResult> {
  const { saved, tracked, rows } = await liveAtlasTickets();
  const db = await patchTicketDatabase();
  let checked = 0, abandoned = 0, unresolved = 0, errors = 0;
  const cvesByTenant = new Map<string, Set<string>>();
  for (const row of rows) {
    if (!cwId(row.id) || tracked.has(row.id) || row.closedFlag !== true) continue; // only closed, untracked tickets are "lost"
    if (!KNOWN_LOST_ATLAS_TICKET_IDS.has(row.id)) continue; // never touch anything outside the confirmed list, even if it matches every other filter
    checked++;
    try {
      const uuid = await draftUuidForTicket(saved.value, row.id);
      if (!uuid) { unresolved++; continue; }
      const draft = (await db.query("SELECT packet, tenant_id FROM patch_group_ticket_requests WHERE id=$1", [uuid])).rows[0] as
        { packet: PatchGroup; tenant_id: string } | undefined;
      if (!draft?.packet?.cves?.length) { unresolved++; continue; }
      const result = await db.query(`UPDATE patch_group_ticket_requests SET state='abandoned',ticket_id=$2,ticket_url=$3,ticket_status=$4,closed=true,
        cw_target=$5,cw_revision=$6,last_error='Closed in ConnectWise before a fix was verified and treated as lost; its CVEs were queued for a fresh ticket where not already covered elsewhere.',updated_at=now()
        WHERE id=$1 AND ticket_id IS NULL`,
        [uuid, row.id, ticketUrl(saved.value, row.id), typeof row.status?.name === "string" ? row.status.name : "Unknown", saved.target, saved.revision]);
      if (!result.rowCount) { unresolved++; continue; } // already adopted or abandoned by a concurrent pass -- leave it alone
      await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.abandoned')", [uuid, ACTOR]);
      abandoned++;
      const cves = cvesByTenant.get(draft.tenant_id) ?? new Set<string>();
      for (const cve of draft.packet.cves) cves.add(cve);
      cvesByTenant.set(draft.tenant_id, cves);
    } catch {
      errors++; // one ticket's lookup or update failing must not block the rest
    }
  }
  if (!cvesByTenant.size) return { checked, abandoned, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved, errors };
  const revision = await dashboardConnectionRevision("crowdstrike");
  if (revision === null) return { checked, abandoned, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved, errors }; // no CrowdStrike connection to re-collect from -- abandonment still stands, replacement waits
  const alreadyTicketed = await activeTicketedPairs();
  let cvesReplaced = 0, cvesNeedsReview = 0, cvesAlreadyCovered = 0;
  for (const [tenantId, cveSet] of cvesByTenant) {
    const cves = [...cveSet];
    try {
      if (cves.length >= 2) {
        const consolidation = await prepareConsolidation({ cves, tenantId, appCompanyId: ATLAS_REPORTING_COMPANY_ID }, revision, alreadyTicketed);
        await persistPreparedGroups(consolidation, ACTOR, revision);
        cvesReplaced += cves.length;
      } else {
        // No group to consolidate into and no single-CVE auto-create path --
        // drafted for a human to review and cut by hand.
        const patchRequest = await preparePatchRequest({ cve: cves[0], tenantId }, revision, alreadyTicketed);
        await persistPreparedPatch(randomUUID(), patchRequest, ACTOR, revision);
        cvesNeedsReview++;
      }
    } catch (err) {
      if (isNothingLeftToReplace(err)) cvesAlreadyCovered += cves.length;
      else errors++; // one tenant's re-collection failing must not block the rest
    }
  }
  return { checked, abandoned, cvesReplaced, cvesNeedsReview, cvesAlreadyCovered, unresolved, errors };
}
