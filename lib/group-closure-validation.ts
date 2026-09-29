import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { dashboardConnectionRevision, verifyAgainstCrowdStrike } from "./elastic-dashboard-store";
import { setGroupTicketPriority } from "./patch-group-ticket-store";
import { cwDefaultOpenStatus, cwAddTicketNote, cwRequest, cwPrioritiesBySort, type CWOption } from "./connectwise-client";
import { targetPriorityFor } from "./group-ticket-priority";
import { runWithConcurrency, syncTable } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import type { PatchGroup } from "./patch-request";

const ACTOR = "closure-validation";
// Same pilot scope as group-auto-create.ts and group-priority-backfill.ts.
const PILOT_COMPANY_IDS = [ATLAS_REPORTING_COMPANY_ID];

type Counts = { checked: number; reopened: number; confirmedFixed: number; needsManualUnmerge: number; errors: number };
type VerifyResult = { checkedAt: string; stillOpenHosts: string[] };
type ClosedRow = { id: string; tenant_id: string; routing: { boardId?: number } | null; packet: PatchGroup; worst_severity: "Critical" | "High" | null };

// ConnectWise's native ticket-merge/combine feature locks a child ticket and
// redirects activity to its parent (confirmed from a live ticket: status
// "Closed Merged", "absorbed as a Child of Ticket #...", edits refused). A
// plain status change can't undo that, and guessing at an unmerge call
// against real production tickets isn't worth the risk -- this is a
// distinct, named outcome so it's never silently folded into "errors".
class MergedTicketError extends Error {}

async function recordVerification(id: string, result: VerifyResult, state: "verified" | "still_open") {
  const db = await patchTicketDatabase();
  await db.query("UPDATE patch_group_ticket_requests SET fix_verified_at=$2,fix_verified_state=$3,fix_still_open_count=$4,updated_at=now() WHERE id=$1",
    [id, result.checkedAt, state, result.stillOpenHosts.length]);
  await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'fix.verified')", [id, ACTOR]);
}

// Closing a ConnectWise ticket and a CVE actually being gone are two
// different facts, and only CrowdStrike's own sensor telemetry -- the same
// source that raised the finding in the first place -- can confirm the
// second one. This puts the ticket back the way it would have looked had it
// never been closed: reopened, with a visible note explaining why, so the
// client sees the correction the same way they saw the closure.
async function reopenTicket(id: string, boardId: number, result: VerifyResult, severity: "Critical" | "High" | null, priorities: CWOption[]) {
  const db = await patchTicketDatabase();
  const row = (await db.query("SELECT ticket_id,cw_target FROM patch_group_ticket_requests WHERE id=$1", [id])).rows[0];
  if (!row?.ticket_id) throw new Error("Missing ticket to reopen.");
  const saved = await savedConnection();
  if (saved.target !== row.cw_target) throw new Error("ConnectWise connection changed before reopening; retry next pass.");
  const status = await cwDefaultOpenStatus(saved.value, boardId);
  // A ticket merged into a parent might still accept a normal status change
  // even though the UI blocks other edits -- there's no confirmed separate
  // "unmerge" API call to guess at, so this just reuses the same PATCH every
  // other reopen uses and lets ConnectWise's own response be the judge. Only
  // a rejection that actually mentions merge/combine is treated as needing
  // manual separation; any other failure is a normal error.
  try {
    await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`, "PATCH", [{ op: "replace", path: "status/id", value: status.id }]);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/merg|combin/i.test(message)) {
      await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
        [id, `ConnectWise refused to reopen this ticket: ${message} It may need to be separated from its parent ticket first.`]);
      await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.reopen.blocked_merged')", [id, ACTOR]);
      throw new MergedTicketError(message);
    }
    throw err;
  }
  await cwAddTicketNote(saved.value, row.ticket_id,
    `Reopened automatically: a rescan on ${new Date(result.checkedAt).toLocaleString()} found this vulnerability still present on ${result.stillOpenHosts.length} host(s). This ticket was closed before the fix was verified and does not reflect completed remediation.`);
  await db.query("UPDATE patch_group_ticket_requests SET closed=false,ticket_status=$2,fix_verified_at=$3,fix_verified_state='still_open',fix_still_open_count=$4,updated_at=now() WHERE id=$1",
    [id, status.name, result.checkedAt, result.stillOpenHosts.length]);
  await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.reopened.unverified_closure')", [id, ACTOR]);
  // Going back live should reassert the ticket's actual severity, not just
  // trust whatever priority it happened to carry into the reopen -- same
  // rule auto-create uses at creation time (Critical -> top, High -> next).
  // Never lets a priority-setting problem undo the reopen itself.
  if (severity) {
    const target = targetPriorityFor(severity, priorities);
    if (target) await setGroupTicketPriority(id, target.id, ACTOR).catch(() => {});
  }
}

// Re-checks every closed Atlas ticket that hasn't already been confirmed
// fixed, and reopens anything closed without a real remediation behind it.
// Once a ticket is confirmed verified it's left alone for good (a
// legitimately fixed ticket has no reason to be re-queried every pass); a
// reopened ticket naturally drops out on its own (closed=false) until
// someone closes it again, at which point this checks it fresh.
export async function validateClosedGroupTickets(): Promise<Counts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 };
  const db = await patchTicketDatabase();
  const rows = (await db.query(`
    SELECT id, tenant_id, routing, packet, worst_severity FROM patch_group_ticket_requests
    WHERE state='created' AND closed=true AND ticket_id IS NOT NULL AND cw_target=$1
      AND packet->>'appCompanyId' = ANY($2::text[])
      AND fix_verified_state IS DISTINCT FROM 'verified'
  `, [saved.target, PILOT_COMPANY_IDS])).rows as ClosedRow[];
  if (!rows.length) return { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 };
  const crowdstrikeRevision = await dashboardConnectionRevision("crowdstrike");
  if (crowdstrikeRevision === null) return { checked: rows.length, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0 };
  // Most-urgent-first; fetched once and reused for every ticket this pass,
  // same as group-auto-create.ts. Missing/unreachable never blocks the
  // reopen -- it just means priority stays whatever it already was.
  const priorities = await cwPrioritiesBySort(saved.value).catch(() => []);
  let reopened = 0, confirmedFixed = 0, needsManualUnmerge = 0, errors = 0;
  await runWithConcurrency(rows, 2, async (row) => {
    const packet = row.packet;
    if (packet.source === "stored-findings" || !packet.hostScope?.length || !row.routing?.boardId) return; // no CrowdStrike scope, or no board, to act on
    try {
      const result = await verifyAgainstCrowdStrike(packet.cves, packet.hostScope, row.tenant_id, crowdstrikeRevision);
      if (result.stillOpenHosts.length === 0) {
        await recordVerification(row.id, result, "verified");
        confirmedFixed++;
        return;
      }
      await reopenTicket(row.id, row.routing.boardId, result, row.worst_severity, priorities);
      reopened++;
    } catch (err) {
      if (err instanceof MergedTicketError) needsManualUnmerge++;
      else errors++; // one ticket's connection mismatch or ConnectWise rejection must not block the rest
    }
  });
  return { checked: rows.length, reopened, confirmedFixed, needsManualUnmerge, errors };
}

// A ticket closed in ConnectWise doesn't reach validateClosedGroupTickets
// until our own tracker's closed flag catches up with it -- previously that
// only happened on ticket-status-sync.ts's own 15-minute pass, so a ticket
// closed without a verified fix could sit looking closed to the client for
// up to two full sync cycles before this reopened it. This refreshes just
// the pilot's own tickets immediately before validating, so "closed"
// effectively means "closed and no rescan has found the CVE since" rather
// than "closed until the next slow sync notices" -- a closure without a
// verified fix behind it gets caught and reversed on this same pass.
export async function syncAndValidateClosedGroupTickets(): Promise<Counts & { synced: number }> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, reopened: 0, confirmedFixed: 0, needsManualUnmerge: 0, errors: 0, synced: 0 };
  const db = await patchTicketDatabase();
  // includeClosed: a ticket someone reopens by hand straight in ConnectWise
  // (as happened to #2655137) needs to fall out of "closed" here too, not
  // just tickets closed since the last check -- otherwise it stays
  // incorrectly marked closed=true forever and looks free for a new
  // consolidated ticket to duplicate. Scoped to the pilot's own tickets
  // (companyIds) precisely because that's only safe to do for a small,
  // known set -- not the whole portfolio on this tighter timer.
  const sync = await syncTable(db, "patch_group_ticket_requests", saved.target, saved.value, { includeClosed: true, companyIds: PILOT_COMPANY_IDS });
  const validation = await validateClosedGroupTickets();
  return { ...validation, synced: sync.updated };
}

const runtime = globalThis as typeof globalThis & { __groupClosureValidation?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__groupClosureValidation ??= {};

export function startClosureValidationScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = syncAndValidateClosedGroupTickets().then(
      () => {},
      (err) => console.error("[group-closure-validation] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  // Tighter than the general 15-minute sync schedulers on purpose: this is
  // the loop that stands between a premature closure and a client seeing it
  // as done, so the gap needs to be minutes, not up to half an hour.
  state.timer = setInterval(trigger, 5 * 60_000);
  state.timer.unref();
  trigger();
}
