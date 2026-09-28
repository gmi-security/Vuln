import { createHash, randomUUID } from "node:crypto";
import { DashboardError } from "./elastic-dashboard";
import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { verifyAgainstCrowdStrike } from "./elastic-dashboard-store";
import { customerFalconTenantIds } from "./reporting-tenant-scope";
import { atlasFalconReviewPacket } from "./reporting-direct-sources";
import type { PatchConsolidation, PatchGroup } from "./patch-request";
import { automatedGroupTicketBody, type PatchGroupTicketSummary } from "./patch-group-ticket-types";
import { cwId, cwRequest, findCWRequest, CWRequestError, parseRouting, ticketUrl, uploadPatchCsv, validateCWRouting, type ConnectWiseConnection, type CWRecord, type TicketRouting } from "./connectwise-client";

const fields = "id,cves,remediation_id,tenant_id,state,review_state,reviewed_by,reviewed_at,prepared_by,created_by,prepared_at,updated_at,host_count,finding_count,labels,ticket_id,ticket_url,ticket_status,closed,attachment_state,last_error,packet->>'title' AS remediation_title,packet->>'source' AS source,packet->>'companyName' AS company_name,fix_verified_at,fix_verified_state,fix_still_open_count,ticket_priority_id,ticket_priority_name,ticket_sla_escalations";
function summary(row: CWRecord): PatchGroupTicketSummary {
  return { id: row.id, cves: row.cves, remediationId: row.remediation_id, remediationTitle: row.remediation_title, tenantId: row.tenant_id, source: row.source === "stored-findings" ? "stored-findings" : "crowdstrike", companyName: row.company_name ?? null, state: row.state,
    reviewState: row.review_state, reviewedBy: row.reviewed_by, reviewedAt: row.reviewed_at ? new Date(row.reviewed_at).toISOString() : null,
    preparedBy: row.prepared_by, createdBy: row.created_by, preparedAt: new Date(row.prepared_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString(),
    hostCount: row.host_count, findingCount: row.finding_count, company: row.labels?.company?.name ?? null, board: row.labels?.board?.name ?? null,
    ticketId: row.ticket_id, ticketUrl: row.ticket_url, ticketStatus: row.ticket_status, closed: row.closed,
    attachmentState: row.attachment_state, error: row.last_error,
    fixVerifiedAt: row.fix_verified_at ? new Date(row.fix_verified_at).toISOString() : null,
    fixVerifiedState: row.fix_verified_state ?? null, fixStillOpenCount: row.fix_still_open_count ?? null,
    priorityId: row.ticket_priority_id ?? null, priorityName: row.ticket_priority_name ?? null,
    slaEscalations: row.ticket_sla_escalations ?? 0 };
}
function requestId(id: string) { if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id)) throw new DashboardError("Patch group request not found.", 404); }

// Persists every ranked patch group from a consolidation run as a draft so a
// ticket can be created for any one of them later, without re-collecting from
// CrowdStrike. Mirrors the single-CVE flow's persistPreparedPatch, one row
// per group instead of one row per whole request.
export async function persistPreparedGroups(consolidation: PatchConsolidation, actor: string, revision: number): Promise<string[]> {
  if (!consolidation.groups.length) return [];
  const db = await patchTicketDatabase(), client = await db.connect();
  const ids = consolidation.groups.map(() => randomUUID());
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(804207)");
    const current = (await client.query("SELECT revision FROM dashboard_source_connections WHERE source='crowdstrike' FOR SHARE")).rows[0];
    if (current?.revision !== revision) throw new DashboardError("CrowdStrike connection changed. Prepare a fresh consolidation.", 409);
    for (const [index, group] of consolidation.groups.entries()) {
      const id = ids[index];
      const scopeHash = createHash("sha256").update(JSON.stringify(group.hostScope)).digest("hex");
      const existing = (await client.query(`SELECT id FROM patch_group_ticket_requests
        WHERE remediation_id=$1 AND tenant_id=$2 AND scope_hash=$3 AND cves=$4::jsonb
        AND state='prepared' AND review_state IN ('pending','approved') ORDER BY prepared_at DESC LIMIT 1`,
        [group.remediationId, group.tenantId, scopeHash, JSON.stringify(group.cves)])).rows[0];
      if (existing) { ids[index] = existing.id; continue; }
      // An analyst's explicit customer selection at build time always wins.
      // Only fall back to the legacy Atlas tenant-CID allowlist for groups
      // built with no customer selected (e.g. an org-wide, unscoped query).
      const packet = group.appCompanyId
        ? group
        : atlasFalconReviewPacket(group, customerFalconTenantIds("CO-147284", process.env.ATLAS_CROWDSTRIKE_TENANT_IDS));
      await client.query(`INSERT INTO patch_group_ticket_requests(id,cves,remediation_id,tenant_id,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,finding_count,scope_hash)
        VALUES($1,$2::jsonb,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11) ON CONFLICT(id) DO NOTHING`,
        [id, JSON.stringify(group.cves), group.remediationId, group.tenantId, actor, consolidation.collectedAt, revision,
          JSON.stringify(packet), group.deviceCount, group.findingCount, scopeHash]);
      await client.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'group.prepared')", [id, actor]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  return ids;
}
async function recoverInterruptedRequests() {
  const db = await patchTicketDatabase();
  await db.query(`UPDATE patch_group_ticket_requests SET state='uncertain',last_error='Creation was interrupted. Check the creation outcome before retrying.',updated_at=now()
    WHERE state='creating' AND started_at < now()-interval '3 minutes'`);
  await db.query(`UPDATE patch_group_ticket_requests SET attachment_state='pending',last_error='CSV attachment was interrupted. Retry the attachment check.',updated_at=now()
    WHERE attachment_state='uploading' AND attachment_started < now()-interval '3 minutes'`);
}
export async function listGroupTickets(reviewOnly = false, page = 1, appCompanyId?: string) {
  if (!Number.isSafeInteger(page) || page < 1 || page > 10000) throw new DashboardError("Invalid queue page.", 400);
  if (appCompanyId && !/^CO-\d+$/.test(appCompanyId)) throw new DashboardError("Invalid customer.", 400);
  const db = await patchTicketDatabase(); await recoverInterruptedRequests();
  const tenantIds = customerFalconTenantIds(appCompanyId ?? "", process.env.ATLAS_CROWDSTRIKE_TENANT_IDS);
  const where = (companyParam: number, tenantParam: number) => `WHERE ($1::boolean = false OR state='prepared') AND
    ($${companyParam}::text IS NULL OR packet->>'appCompanyId'=$${companyParam} OR
      (lower(tenant_id) = ANY($${tenantParam}::text[]) AND COALESCE(packet->>'source','crowdstrike')='crowdstrike'))`;
  const params = [reviewOnly, (page - 1) * 100, appCompanyId ?? null, tenantIds];
  // The review queue (reviewOnly) is where an analyst decides what to work
  // on next, so its pending bucket is ranked by devices affected — the same
  // "biggest bang for buck" measure used everywhere else this app ranks
  // remediations — not by recency. Approved/other rows, and the full
  // (non-review) tracker, keep the original prepared_at-newest-first order.
  const rows = await db.query(`SELECT ${fields} FROM patch_group_ticket_requests
    ${where(3, 4)}
    ORDER BY CASE WHEN $1::boolean THEN CASE review_state WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END ELSE 0 END,
      CASE WHEN $1::boolean AND review_state='pending' THEN host_count END DESC NULLS LAST,
      CASE WHEN $1::boolean AND review_state='pending' THEN finding_count END DESC NULLS LAST,
      prepared_at DESC LIMIT 101 OFFSET $2`, params);
  const counts = await db.query(`SELECT COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE review_state='pending')::int AS pending,
    COUNT(*) FILTER (WHERE review_state='approved')::int AS approved
    FROM patch_group_ticket_requests ${where(2, 3)}`, [reviewOnly, appCompanyId ?? null, tenantIds]);
  return { requests: rows.rows.slice(0, 100).map(summary), more: rows.rows.length > 100,
    total: counts.rows[0]?.total ?? 0, pending: counts.rows[0]?.pending ?? 0, approved: counts.rows[0]?.approved ?? 0 };
}
export async function readGroupTicket(id: string, withPacket = false) {
  requestId(id); const db = await patchTicketDatabase(); await recoverInterruptedRequests();
  const row = (await db.query(`SELECT ${fields}${withPacket ? ",packet" : ""} FROM patch_group_ticket_requests WHERE id=$1`, [id])).rows[0];
  if (!row) throw new DashboardError("Patch group request not found.", 404);
  return { request: summary(row), ...(withPacket ? { group: row.packet as PatchGroup } : {}) };
}
export async function reviewGroupTicket(id: string, action: "approve" | "dismiss" | "reopen", actor: string) {
  requestId(id);
  const db = await patchTicketDatabase();
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const row = (await client.query("SELECT state, review_state FROM patch_group_ticket_requests WHERE id=$1 FOR UPDATE", [id])).rows[0];
    if (!row) throw new DashboardError("Patch group request not found.", 404);
    if (row.state !== "prepared") throw new DashboardError("A ticket request has already been started for this draft.", 409);
    const next = action === "approve" ? "approved" : action === "dismiss" ? "dismissed" : "pending";
    if (row.review_state === next) { await client.query("COMMIT"); return readGroupTicket(id); }
    if (action === "reopen" && row.review_state !== "dismissed") throw new DashboardError("Only dismissed drafts can be reopened.", 409);
    if (action !== "reopen" && row.review_state !== "pending") throw new DashboardError("Reopen this draft before reviewing it again.", 409);
    await client.query(`UPDATE patch_group_ticket_requests SET review_state=$2,reviewed_by=$3,reviewed_at=now(),updated_at=now() WHERE id=$1`, [id, next, actor]);
    await client.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,$3)", [id, actor, `review.${action}`]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  return readGroupTicket(id);
}
const workers = new Set<string>();
function background(id: string, work: () => Promise<void>) {
  if (workers.has(id)) return;
  workers.add(id);
  void work().catch(() => console.error("[patch-group-tickets] Request processing interrupted; check its saved state.")).finally(() => workers.delete(id));
}

export async function createGroupTicket(id: string, value: unknown, actor: string) {
  requestId(id); const body = value as CWRecord;
  const routing = parseRouting(body?.routing);
  if (typeof body.title !== "string" || !body.title.trim() || body.title.length > 100 || typeof body.body !== "string" || !body.body.trim() || body.body.length > 200000) throw new DashboardError("Provide a ticket title of at most 100 characters and ticket contents of at most 200,000 characters.");
  const saved = await savedConnection(), db = await patchTicketDatabase(), client = await db.connect();
  let start = false;
  try {
    await client.query("BEGIN"); await client.query("SELECT pg_advisory_xact_lock(804206)");
    const row = (await client.query("SELECT * FROM patch_group_ticket_requests WHERE id=$1 FOR UPDATE", [id])).rows[0];
    if (!row) throw new DashboardError("Patch group request not found.", 404);
    if (["creating", "uncertain", "created"].includes(row.state)) { await client.query("COMMIT"); return readGroupTicket(id); }
    if (row.review_state !== "approved") throw new DashboardError("Approve this consolidation in the review queue before sending a ticket.", 409);
    const packet = row.packet as PatchGroup;
    if (packet.source !== "stored-findings") {
      const cs = (await client.query("SELECT revision FROM dashboard_source_connections WHERE source='crowdstrike' FOR SHARE")).rows[0];
      if (cs?.revision !== row.crowdstrike_revision) throw new DashboardError("CrowdStrike connection changed. Prepare a fresh consolidation before sending.", 409);
    }
    const cw = (await client.query("SELECT revision FROM patch_connectwise_connection WHERE id=1 FOR SHARE")).rows[0];
    if (cw?.revision !== saved.revision || body.connectionRevision !== saved.revision) throw new DashboardError("ConnectWise connection changed. Reload its options before sending.", 409);
    const existing = (await client.query(`SELECT id,ticket_id FROM patch_group_ticket_requests WHERE cw_target=$1 AND remediation_id=$2 AND tenant_id=$3 AND company_id=$4 AND scope_hash=$5
      AND state IN ('creating','uncertain','created') AND closed=false AND id<>$6 LIMIT 1`, [saved.target, row.remediation_id, row.tenant_id, routing.companyId, row.scope_hash, id])).rows[0];
    if (existing) throw new DashboardError(`This patch and device scope already has ${existing.ticket_id ? `ticket #${existing.ticket_id}` : "a ticket request in progress"}. Open its saved request below.`, 409);
    await client.query(`UPDATE patch_group_ticket_requests SET state='creating',created_by=$2,cw_target=$3,cw_revision=$4,company_id=$5,routing=$6::jsonb,title=$7,body=$8,
      started_at=now(),updated_at=now(),last_error=NULL WHERE id=$1`, [id, actor, saved.target, saved.revision, routing.companyId, JSON.stringify(routing), body.title.trim(), body.body.trim()]);
    await client.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.requested')", [id, actor]);
    await client.query("COMMIT"); start = true;
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  if (start) background(id, () => runCreation(id));
  return readGroupTicket(id);
}
async function recordTicket(id: string, ticket: CWRecord, connection: ConnectWiseConnection) {
  if (!cwId(ticket?.id)) throw new CWRequestError("ConnectWise did not return a ticket number. Check the creation outcome.", true);
  const db = await patchTicketDatabase();
  await db.query(`UPDATE patch_group_ticket_requests SET state='created',ticket_id=$2,ticket_url=$3,ticket_status=$4,closed=$5,attachment_state='pending',last_error=NULL,updated_at=now() WHERE id=$1 AND ticket_id IS NULL`,
    [id, ticket.id, ticketUrl(connection, ticket.id), typeof ticket.status?.name === "string" ? ticket.status.name : "Created", ticket.closedFlag === true]);
}
async function runCreation(id: string) {
  const db = await patchTicketDatabase(); let writeStarted = false, ticketSaved = false;
  try {
    const row = (await db.query("SELECT * FROM patch_group_ticket_requests WHERE id=$1", [id])).rows[0];
    if (row?.state !== "creating") return;
    const saved = await savedConnection();
    if (saved.revision !== row.cw_revision || saved.target !== row.cw_target) throw new DashboardError("ConnectWise connection changed before sending. Review and submit again.");
    const labels = await validateCWRouting(saved.value, row.routing as TicketRouting);
    await db.query("UPDATE patch_group_ticket_requests SET labels=$2::jsonb,updated_at=now() WHERE id=$1", [id, JSON.stringify(labels)]);
    const current = await savedConnection();
    if (current.revision !== saved.revision) throw new DashboardError("ConnectWise connection changed before sending. Review and submit again.");
    writeStarted = true;
    const ticket = await cwRequest(saved.value, "/service/tickets", "POST", { summary: row.title, initialDescription: row.body, recordType: "ServiceTicket",
      board: { id: row.routing.boardId }, company: { id: row.routing.companyId },
      ...(row.routing.teamId ? { team: { id: row.routing.teamId } } : {}), externalXRef: `GMI-GRP-${id}` });
    await recordTicket(id, ticket, saved.value); ticketSaved = true;
    await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.created')", [id, row.created_by]);
    await attachCsv(id, row.created_by);
  } catch (error) {
    const message = error instanceof DashboardError ? error.message : "The request was interrupted. Check its saved state before retrying.";
    const uncertain = writeStarted && (!(error instanceof CWRequestError) || error.uncertain);
    await db.query(`UPDATE patch_group_ticket_requests SET state=CASE WHEN ticket_id IS NOT NULL THEN 'created' ELSE $2 END,
      last_error=$3,updated_at=now() WHERE id=$1`, [id, ticketSaved || uncertain ? "uncertain" : "failed", message]);
  }
}
async function attachCsv(id: string, actor: string) {
  const db = await patchTicketDatabase();
  const row = (await db.query(`UPDATE patch_group_ticket_requests SET attachment_state='uploading',attachment_started=now(),updated_at=now()
    WHERE id=$1 AND ticket_id IS NOT NULL AND attachment_state IN ('pending','not_started') RETURNING *`, [id])).rows[0];
  if (!row) return;
  try {
    const saved = await savedConnection();
    if (saved.target !== row.cw_target) throw new DashboardError("Connect the original ConnectWise account to attach this report.");
    const ticket = await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`);
    if (ticket.id !== row.ticket_id || ticket.company?.id !== row.company_id || ticket.externalXRef !== `GMI-GRP-${id}`) throw new DashboardError("The ticket's company or request reference changed. Review the ticket before attaching customer data.");
    const packet = row.packet as PatchGroup;
    const documentId = await uploadPatchCsv(saved.value, row.ticket_id, id, packet.label, packet.csv);
    await db.query("UPDATE patch_group_ticket_requests SET attachment_state='attached',document_id=$2,last_error=NULL,updated_at=now() WHERE id=$1", [id, documentId]);
    await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'csv.attached')", [id, actor]);
  } catch (error) {
    await db.query("UPDATE patch_group_ticket_requests SET attachment_state='pending',last_error=$2,updated_at=now() WHERE id=$1", [id, error instanceof DashboardError ? error.message : "CSV upload was interrupted. Retry the attachment check."]);
  }
}
// Closed-loop verification re-collects from CrowdStrike, so it runs on the
// same background job queue as prepare/consolidate rather than as an instant
// ticket action — it can take as long as preparing the original plan.
export async function verifyGroupTicketFix(id: string, actor: string, revision: number) {
  requestId(id);
  const db = await patchTicketDatabase();
  const row = (await db.query("SELECT tenant_id,packet,ticket_id FROM patch_group_ticket_requests WHERE id=$1", [id])).rows[0];
  if (!row) throw new DashboardError("Patch group request not found.", 404);
  if (!row.ticket_id) throw new DashboardError("Create the ConnectWise ticket before verifying the fix.");
  const packet = row.packet as PatchGroup;
  if (packet.source === "stored-findings") throw new DashboardError("Use the source scanner to verify this customer's findings. CrowdStrike verification applies only to Falcon patch groups.", 409);
  if (!packet.hostScope?.length) throw new DashboardError("This saved plan has no device scope to verify. Prepare a fresh consolidation.");
  const result = await verifyAgainstCrowdStrike(packet.cves, packet.hostScope, row.tenant_id, revision);
  const verifiedState = result.stillOpenHosts.length === 0 ? "verified" : "still_open";
  await db.query("UPDATE patch_group_ticket_requests SET fix_verified_at=$2,fix_verified_state=$3,fix_still_open_count=$4,updated_at=now() WHERE id=$1",
    [id, result.checkedAt, verifiedState, result.stillOpenHosts.length]);
  await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'fix.verified')", [id, actor]);
  return readGroupTicket(id);
}
export async function groupTicketAction(id: string, action: unknown, actor: string) {
  requestId(id); await recoverInterruptedRequests();
  const db = await patchTicketDatabase(), row = (await db.query("SELECT * FROM patch_group_ticket_requests WHERE id=$1", [id])).rows[0];
  if (!row) throw new DashboardError("Patch group request not found.", 404);
  if (action === "retry-attachment") {
    if (!row.ticket_id) throw new DashboardError("Resolve the ticket creation outcome first.");
    background(id, () => attachCsv(id, actor));
    return readGroupTicket(id);
  }
  if (action !== "reconcile" && action !== "check-status") throw new DashboardError("Choose a supported ticket action.");
  const saved = await savedConnection();
  if (saved.target !== row.cw_target) throw new DashboardError("Connect the original ConnectWise account to check this request.");
  if (row.state === "creating") throw new DashboardError("Ticket creation is still in progress. Wait for it to finish.", 409);
  const ticket = row.ticket_id ? await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`) : await findCWRequest(saved.value, `GMI-GRP-${id}`);
  if (!ticket) throw new DashboardError("No matching ticket is visible yet. Check ConnectWise and try this check again; another ticket has not been sent.", 409);
  if (ticket.company?.id !== row.company_id || ticket.externalXRef !== `GMI-GRP-${id}` || (row.ticket_id && ticket.id !== row.ticket_id)) throw new DashboardError("The ticket no longer matches this request's company and reference. Review it in ConnectWise.", 409);
  if (!row.ticket_id) await recordTicket(id, ticket, saved.value);
  await db.query("UPDATE patch_group_ticket_requests SET ticket_status=$2,closed=$3,ticket_priority_id=$4,ticket_priority_name=$5,last_error=NULL,updated_at=now() WHERE id=$1",
    [id, ticket.status?.name ?? "Unknown", ticket.closedFlag === true, cwId(ticket.priority?.id) ? ticket.priority.id : null, typeof ticket.priority?.name === "string" ? ticket.priority.name : null]);
  await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,$3)", [id, actor, action === "reconcile" ? "ticket.reconciled" : "ticket.status.checked"]);
  return readGroupTicket(id);
}
// Raises or lowers an existing ticket's priority directly in ConnectWise — a
// human still picks the value (fetched live from ConnectWise, same as the
// board/team pickers), this just applies it without leaving the app.
export async function setGroupTicketPriority(id: string, priorityId: unknown, actor: string) {
  requestId(id); await recoverInterruptedRequests();
  if (!cwId(priorityId)) throw new DashboardError("Choose a valid ConnectWise priority.");
  const db = await patchTicketDatabase(), row = (await db.query("SELECT ticket_id,cw_target FROM patch_group_ticket_requests WHERE id=$1", [id])).rows[0];
  if (!row) throw new DashboardError("Patch group request not found.", 404);
  if (!row.ticket_id) throw new DashboardError("Create the ConnectWise ticket before changing its priority.");
  const saved = await savedConnection();
  if (saved.target !== row.cw_target) throw new DashboardError("Connect the original ConnectWise account to change this ticket's priority.");
  const ticket = await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`, "PATCH", [{ op: "replace", path: "priority/id", value: priorityId }]);
  await db.query("UPDATE patch_group_ticket_requests SET ticket_priority_id=$2,ticket_priority_name=$3,last_error=NULL,updated_at=now() WHERE id=$1",
    [id, cwId(ticket.priority?.id) ? ticket.priority.id : priorityId, typeof ticket.priority?.name === "string" ? ticket.priority.name : null]);
  await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.priority.changed')", [id, actor]);
  return readGroupTicket(id);
}
export { automatedGroupTicketBody };
