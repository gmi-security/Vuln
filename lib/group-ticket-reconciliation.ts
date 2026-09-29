import { randomUUID } from "node:crypto";
import { patchTicketDatabase, savedConnection, activeTicketedPairs, persistPreparedPatch } from "./patch-ticket-store";
import { persistPreparedGroups } from "./patch-group-ticket-store";
import { dashboardConnectionRevision, prepareConsolidation, preparePatchRequest } from "./elastic-dashboard-store";
import { cwRequest, cwId, ticketUrl, cwDefaultClosedStatus, cwAddTicketNote, type CWRecord, type ConnectWiseConnection } from "./connectwise-client";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { DashboardError } from "./elastic-dashboard";
import { recordJobRun } from "./background-job-runs";
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

// The confirmed 37 above plus the parent they were merged into (#2655137,
// CVE-2026-68839, 1286 devices) -- the full set closeAndRecutMergedAtlas-
// Tickets is allowed to touch, by explicit request: given ConnectWise
// permissions to Combine/Merge tickets aren't changing, the fix here isn't
// to unmerge (not reliably possible via the API) but to stop using this
// specific parent/child structure at all -- close every one of the 38 and
// recut its CVEs as clean, standalone tickets through the normal
// consolidated-patch-plan pipeline, ranked by device impact same as
// everywhere else in this app.
const KNOWN_MERGED_ATLAS_TICKET_IDS = new Set([...KNOWN_LOST_ATLAS_TICKET_IDS, 2655137]);

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
// Advisory-lock key -- same reasoning and numbering scheme as
// VALIDATE_LOCK_KEY in group-closure-validation.ts (804209): the
// UPDATE ... WHERE ticket_id IS NULL guard already stops two concurrent
// passes from double-abandoning the same ticket, but nothing stopped two
// instances from both re-collecting the same CVEs from CrowdStrike at once
// -- wasted work, not a correctness bug, but avoidable the same way.
const ABANDON_LOCK_KEY = 804210;

export async function abandonAndReplaceUntrackedAtlasTickets(): Promise<AbandonResult> {
  const db = await patchTicketDatabase();
  const lockClient = await db.connect();
  const acquired = (await lockClient.query(`SELECT pg_try_advisory_lock(${ABANDON_LOCK_KEY}) AS locked`)).rows[0].locked as boolean;
  if (!acquired) { lockClient.release(); return { checked: 0, abandoned: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0 }; }
  try {
    return await runAbandonAndReplace(db);
  } finally {
    await lockClient.query(`SELECT pg_advisory_unlock(${ABANDON_LOCK_KEY})`).catch(() => {});
    lockClient.release();
  }
}

async function runAbandonAndReplace(db: Awaited<ReturnType<typeof patchTicketDatabase>>): Promise<AbandonResult> {
  const { saved, tracked, rows } = await liveAtlasTickets();
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
  const replaced = await replaceCvesWithFreshDrafts(cvesByTenant);
  if (!replaced) return { checked, abandoned, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved, errors }; // no CrowdStrike connection to re-collect from -- abandonment still stands, replacement waits
  return { checked, abandoned, ...replaced, errors: errors + replaced.errors, unresolved };
}

type ReplaceCounts = { cvesReplaced: number; cvesNeedsReview: number; cvesAlreadyCovered: number; errors: number };

// Shared by runAbandonAndReplace and runCloseAndRecut: given every CVE that
// needs a fresh ticket, grouped by CrowdStrike tenant (never mixed across
// tenants -- see liveAtlasTickets), re-collects each tenant's current live
// findings and queues a normal consolidated draft, same as any other ticket
// in this app -- ranked by devices reached per remediation action, i.e. the
// biggest reduction in risk per patch, which is how this pipeline already
// prioritizes everywhere else. activeTicketedPairs excludes anything a
// still-open tracked ticket elsewhere already covers, so nothing here is
// ever duplicated. Returns null only when there's no CrowdStrike connection
// to collect from at all -- the caller's own state (abandoned/superseded)
// still stands either way; replacement just has to wait for one.
async function replaceCvesWithFreshDrafts(cvesByTenant: Map<string, Set<string>>): Promise<ReplaceCounts | null> {
  const revision = await dashboardConnectionRevision("crowdstrike");
  if (revision === null) return null;
  const alreadyTicketed = await activeTicketedPairs();
  let cvesReplaced = 0, cvesNeedsReview = 0, cvesAlreadyCovered = 0, errors = 0;
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
  return { cvesReplaced, cvesNeedsReview, cvesAlreadyCovered, errors };
}

const abandonRuntime = globalThis as typeof globalThis & { __groupTicketAbandon?: { working?: Promise<void> } };
const abandonState = abandonRuntime.__groupTicketAbandon ??= {};

// A live CrowdStrike re-collection (prepareConsolidation/preparePatchRequest,
// up to a 10-minute budget each) can run per tenant here -- the dashboard's
// request client aborts after a flat 20 seconds, so a button click that
// awaited this whole function would time out the moment there was real work
// to do. This starts the pass and returns immediately without waiting for
// it; `started: false` just means a pass was already running, not a
// failure -- that pass covers this request too.
const ABANDON_JOB = "abandon-and-replace";
export function triggerAbandonAndReplaceNow(): { started: boolean } {
  if (abandonState.working) return { started: false };
  recordJobRun(ABANDON_JOB, "running").catch(() => {});
  abandonState.working = abandonAndReplaceUntrackedAtlasTickets().then(
    (result) => { recordJobRun(ABANDON_JOB, "succeeded", result).catch(() => {}); },
    (err) => {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[group-ticket-reconciliation] Abandon-and-replace pass could not complete:", message);
      recordJobRun(ABANDON_JOB, "failed", undefined, message).catch(() => {});
    },
  ).finally(() => { abandonState.working = undefined; });
  return { started: true };
}

export type RecutResult = { checked: number; closed: number; cvesReplaced: number; cvesNeedsReview: number; cvesAlreadyCovered: number; unresolved: number; errors: number; firstError: string | null };
type TrackedRow = { id: string; cves: string[]; tenantId: string; boardId: number | null };

async function findTrackedRow(
  db: Awaited<ReturnType<typeof patchTicketDatabase>>, ticketId: number, target: string,
): Promise<{ table: "patch_group_ticket_requests" | "patch_ticket_requests"; row: TrackedRow } | null> {
  const group = (await db.query(
    "SELECT id, packet, tenant_id, routing FROM patch_group_ticket_requests WHERE ticket_id=$1 AND cw_target=$2 AND state='created'",
    [ticketId, target],
  )).rows[0] as { id: string; packet: PatchGroup; tenant_id: string; routing: { boardId?: number } | null } | undefined;
  if (group) return { table: "patch_group_ticket_requests", row: { id: group.id, cves: group.packet.cves, tenantId: group.tenant_id, boardId: group.routing?.boardId ?? null } };
  // #2655137 (the parent) went through the single-CVE flow, not the group one
  // -- see the note on liveAtlasTickets above -- so a ticket in this 38-set
  // can just as easily be tracked over here. Unlike the group table, this
  // one has no single tenant_id column -- a single-CVE request can span
  // several tenants, so it's tenant_ids (plural, JSONB array); the first is
  // used here since every ticket seen in this incident only ever had one.
  const single = (await db.query(
    "SELECT id, packet, tenant_ids, routing FROM patch_ticket_requests WHERE ticket_id=$1 AND cw_target=$2 AND state='created'",
    [ticketId, target],
  )).rows[0] as { id: string; packet: { cve: string }; tenant_ids: string[]; routing: { boardId?: number } | null } | undefined;
  if (single) return { table: "patch_ticket_requests", row: { id: single.id, cves: [single.packet.cve], tenantId: single.tenant_ids?.[0] ?? "", boardId: single.routing?.boardId ?? null } };
  return null;
}

// Advisory-lock key -- same numbering scheme as VALIDATE_LOCK_KEY (804209)
// and ABANDON_LOCK_KEY (804210).
const RECUT_LOCK_KEY = 804211;

export async function closeAndRecutMergedAtlasTickets(): Promise<RecutResult> {
  const db = await patchTicketDatabase();
  const lockClient = await db.connect();
  const acquired = (await lockClient.query(`SELECT pg_try_advisory_lock(${RECUT_LOCK_KEY}) AS locked`)).rows[0].locked as boolean;
  if (!acquired) { lockClient.release(); return { checked: 0, closed: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0, firstError: null }; }
  try {
    return await runCloseAndRecut(db);
  } finally {
    await lockClient.query(`SELECT pg_advisory_unlock(${RECUT_LOCK_KEY})`).catch(() => {});
    lockClient.release();
  }
}

// Explicit, by request: rather than leaving these 38 tickets under a
// parent/child structure that can't be reliably undone through the API,
// this closes every one of them for real in ConnectWise -- with a note
// explaining why, immediately replaced, never left closed with nothing
// tracking the underlying risk the way the original incident did -- and
// queues every CVE they covered for a fresh, standalone ticket through the
// normal consolidated-patch-plan pipeline (see replaceCvesWithFreshDrafts).
// Closing happens before the row is marked superseded, so a ConnectWise
// failure leaves the row exactly as it was: tracked, untouched, still
// covered by the normal closure-validation loop.
async function runCloseAndRecut(db: Awaited<ReturnType<typeof patchTicketDatabase>>): Promise<RecutResult> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, closed: 0, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved: 0, errors: 0, firstError: null };
  let checked = 0, closed = 0, unresolved = 0, errors = 0;
  let firstError: string | null = null;
  const cvesByTenant = new Map<string, Set<string>>();
  for (const ticketId of KNOWN_MERGED_ATLAS_TICKET_IDS) {
    checked++;
    let found: Awaited<ReturnType<typeof findTrackedRow>> = null;
    try {
      found = await findTrackedRow(db, ticketId, saved.target);
      if (!found) { unresolved++; continue; } // already superseded by a previous pass, or not actually tracked yet -- leave it alone
      const { table, row } = found;
      if (!row.boardId) { unresolved++; continue; } // no board on record to look up a closed status for -- do not guess
      const closedStatus = await cwDefaultClosedStatus(saved.value, row.boardId);
      await cwRequest(saved.value, `/service/tickets/${ticketId}`, "PATCH", [{ op: "replace", path: "status/id", value: closedStatus.id }]);
      await cwAddTicketNote(saved.value, ticketId,
        "Closed and replaced by a new standalone ticket: this ticket was part of a Combined/merged parent-child group, which can't be reliably separated through the ConnectWise API. Its CVE(s) are being recut as a clean, independent ticket instead so nothing is left tracked under a merged structure.");
      const auditTable = table === "patch_group_ticket_requests" ? "patch_group_ticket_audit" : "patch_ticket_audit";
      await db.query(`UPDATE ${table} SET state='superseded',closed=true,ticket_status=$2,last_error=NULL,updated_at=now() WHERE id=$1`, [row.id, closedStatus.name]);
      await db.query(`INSERT INTO ${auditTable}(request_id,actor,action) VALUES($1,$2,'ticket.superseded')`, [row.id, ACTOR]);
      closed++;
      const cves = cvesByTenant.get(row.tenantId) ?? new Set<string>();
      for (const cve of row.cves) cves.add(cve);
      cvesByTenant.set(row.tenantId, cves);
    } catch (err) {
      errors++; // one ticket's lookup or ConnectWise call failing must not block the rest
      // 38/38 failing with nothing recorded meant no way to tell why -- see
      // the same fix already shipped for closure-validation. Best-effort:
      // never let a failure writing this mask the original error. Also kept
      // on the result itself (firstError) so it shows up straight in the
      // job-status check, without having to find the right row in the table.
      const message = err instanceof Error ? err.message : String(err);
      firstError ??= `#${ticketId}: ${message}`;
      if (found) {
        await db.query(`UPDATE ${found.table} SET last_error=$2,updated_at=now() WHERE id=$1`, [found.row.id, message]).catch(() => {});
      }
    }
  }
  if (!cvesByTenant.size) return { checked, closed, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved, errors, firstError };
  const replaced = await replaceCvesWithFreshDrafts(cvesByTenant);
  if (!replaced) return { checked, closed, cvesReplaced: 0, cvesNeedsReview: 0, cvesAlreadyCovered: 0, unresolved, errors, firstError }; // closures still stand -- replacement waits for a CrowdStrike connection
  return { checked, closed, ...replaced, errors: errors + replaced.errors, unresolved, firstError };
}

const recutRuntime = globalThis as typeof globalThis & { __groupTicketRecut?: { working?: Promise<void> } };
const recutState = recutRuntime.__groupTicketRecut ??= {};

// Same reasoning as triggerAbandonAndReplaceNow: closing 38 tickets plus a
// live CrowdStrike re-collection is reliably past the dashboard's
// 20-second request timeout. Starts the pass and returns immediately.
const RECUT_JOB = "close-and-recut";
export function triggerCloseAndRecutNow(): { started: boolean } {
  if (recutState.working) return { started: false };
  recordJobRun(RECUT_JOB, "running").catch(() => {});
  recutState.working = closeAndRecutMergedAtlasTickets().then(
    (result) => { recordJobRun(RECUT_JOB, "succeeded", result).catch(() => {}); },
    (err) => {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[group-ticket-reconciliation] Close-and-recut pass could not complete:", message);
      recordJobRun(RECUT_JOB, "failed", undefined, message).catch(() => {});
    },
  ).finally(() => { recutState.working = undefined; });
  return { started: true };
}
