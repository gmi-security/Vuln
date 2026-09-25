import { createHash } from "node:crypto";
import { DashboardError } from "./elastic-dashboard";
import { dashboardDatabase } from "./elastic-dashboard-store";
import { parsePatchInput, type PatchRequest } from "./patch-request";
import { automatedTicketBody, type PatchTicketSummary } from "./patch-ticket-types";
import { cwId, cwOptions, cwRequest, cwTarget, CWRequestError, findCWRequest, normalizeCWEndpoint, openCWConnection, parseCWConnection, parseRouting,
  sealCWConnection, ticketUrl, uploadPatchCsv, validateCWRouting, type ConnectWiseConnection, type CWDefaults, type CWRecord, type TicketRouting } from "./connectwise-client";

let ready: Promise<void> | undefined;
export async function patchTicketDatabase() {
  const db = await dashboardDatabase();
  ready ??= db.query(`CREATE TABLE IF NOT EXISTS patch_connectwise_connection (
    id INT PRIMARY KEY CHECK(id=1), secret TEXT NOT NULL, revision INT NOT NULL DEFAULT 1,
    target TEXT NOT NULL, defaults JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS patch_ticket_requests (
    id UUID PRIMARY KEY, cve TEXT NOT NULL, prepared_by TEXT NOT NULL, created_by TEXT,
    prepared_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    crowdstrike_revision INT NOT NULL, packet JSONB NOT NULL, host_count INT NOT NULL,
    tenant_ids JSONB NOT NULL, scope_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'prepared',
    cw_target TEXT, cw_revision INT, company_id INT, routing JSONB, labels JSONB,
    title TEXT, body TEXT, started_at TIMESTAMPTZ, ticket_id INT, ticket_url TEXT, ticket_status TEXT,
    closed BOOLEAN NOT NULL DEFAULT false, attachment_state TEXT NOT NULL DEFAULT 'not_started',
    attachment_started TIMESTAMPTZ, document_id INT, last_error TEXT
  );
  CREATE INDEX IF NOT EXISTS patch_ticket_cve_date ON patch_ticket_requests(cve, prepared_at DESC);
  CREATE UNIQUE INDEX IF NOT EXISTS patch_ticket_active_scope ON patch_ticket_requests(cw_target,cve,company_id,scope_hash)
    WHERE state IN ('creating','uncertain','created') AND closed=false;
  CREATE TABLE IF NOT EXISTS patch_ticket_audit (
    id BIGSERIAL PRIMARY KEY, request_id UUID, actor TEXT NOT NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`).then(() => {}).catch(error => { ready = undefined; throw error; });
  await ready;
  return db;
}
const fields = "id,cve,state,prepared_by,created_by,prepared_at,updated_at,host_count,tenant_ids,labels,ticket_id,ticket_url,ticket_status,closed,attachment_state,last_error";
function summary(row: CWRecord): PatchTicketSummary {
  return { id: row.id, cve: row.cve, state: row.state, preparedBy: row.prepared_by, createdBy: row.created_by,
    preparedAt: new Date(row.prepared_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString(), hostCount: row.host_count,
    tenantIds: row.tenant_ids, company: row.labels?.company?.name ?? null, board: row.labels?.board?.name ?? null,
    ticketId: row.ticket_id, ticketUrl: row.ticket_url, ticketStatus: row.ticket_status, closed: row.closed,
    attachmentState: row.attachment_state, error: row.last_error };
}
function requestId(id: string) { if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id)) throw new DashboardError("Patch request not found.", 404); }
async function savedConnection(): Promise<{ value: ConnectWiseConnection; revision: number; target: string; defaults: CWDefaults }> {
  const db = await patchTicketDatabase(), row = (await db.query("SELECT * FROM patch_connectwise_connection WHERE id=1")).rows[0];
  if (!row) throw new DashboardError("Add your ConnectWise connection under Connections first.", 409);
  return { value: openCWConnection(row.secret), revision: row.revision, target: row.target, defaults: row.defaults };
}
export async function readCWSettings() {
  const db = await patchTicketDatabase(), row = (await db.query("SELECT * FROM patch_connectwise_connection WHERE id=1")).rows[0];
  if (!row) return { configured: false, defaults: {} };
  try {
    const connection = openCWConnection(row.secret);
    return { configured: true, endpoint: connection.endpoint, companyId: connection.companyId, clientId: connection.clientId, revision: row.revision, defaults: row.defaults };
  } catch { return { configured: false, defaults: {}, error: "Re-enter your ConnectWise keys to restore the connection." }; }
}
export async function saveCWSettings(value: unknown, actor: string) {
  const db = await patchTicketDatabase(), body = value as CWRecord;
  if (!body || typeof body !== "object") throw new DashboardError("Enter the connection settings.");
  const existing = (await db.query("SELECT * FROM patch_connectwise_connection WHERE id=1")).rows[0];
  const endpoint = normalizeCWEndpoint(body.endpoint);
  let candidate: CWRecord = { ...body, endpoint };
  if ((!body.publicKey || !body.privateKey) && existing) {
    const old = openCWConnection(existing.secret);
    if (old.endpoint !== endpoint || old.companyId !== body.companyId?.trim() || old.clientId !== body.clientId?.trim()) throw new DashboardError("Enter both keys when changing the ConnectWise address, company ID, or Client ID.");
    candidate = { ...candidate, publicKey: body.publicKey || old.publicKey, privateKey: body.privateKey || old.privateKey };
  }
  const connection = parseCWConnection(candidate);
  // Test with a read-only board request. No sample ticket is created.
  const boards = await cwOptions(connection, "boards");
  const client = await db.connect();
  try {
    await client.query("BEGIN"); await client.query("SELECT pg_advisory_xact_lock(804205)");
    const current = (await client.query("SELECT revision FROM patch_connectwise_connection WHERE id=1 FOR UPDATE")).rows[0];
    if ((current?.revision ?? null) !== (existing?.revision ?? null)) throw new DashboardError("The connection was updated by another member. Reload and try again.", 409);
    await client.query(`INSERT INTO patch_connectwise_connection(id,secret,target) VALUES(1,$1,$2)
      ON CONFLICT(id) DO UPDATE SET secret=EXCLUDED.secret,target=EXCLUDED.target,revision=patch_connectwise_connection.revision+1,
      defaults=CASE WHEN patch_connectwise_connection.target=EXCLUDED.target THEN patch_connectwise_connection.defaults ELSE '{}'::jsonb END,updated_at=now()`, [sealCWConnection(connection), cwTarget(connection)]);
    await client.query("INSERT INTO patch_ticket_audit(actor,action) VALUES($1,'connection.saved')", [actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  return { ...(await readCWSettings()), boards };
}
export async function saveCWDefaults(value: unknown, actor: string) {
  const parsed = parseRouting({ ...(value as object), companyId: 1 });
  const { companyId: _unused, ...defaults } = parsed;
  const saved = await savedConnection();
  await validateCWRouting(saved.value, defaults);
  const db = await patchTicketDatabase();
  const result = await db.query("UPDATE patch_connectwise_connection SET defaults=$1::jsonb,updated_at=now() WHERE id=1 AND revision=$2 RETURNING id", [JSON.stringify(defaults), saved.revision]);
  if (!result.rowCount) throw new DashboardError("The connection changed. Reload routing options.", 409);
  await db.query("INSERT INTO patch_ticket_audit(actor,action) VALUES($1,'routing.defaults.saved')", [actor]);
  return readCWSettings();
}
export async function readCWOptions(kind: string, boardId?: number, page = 1, search = "", selectedId?: number) {
  const saved = await savedConnection();
  return { ...(await cwOptions(saved.value, kind, boardId, page, search, selectedId)), revision: saved.revision };
}

export async function persistPreparedPatch(id: string, packet: PatchRequest, actor: string, revision: number) {
  requestId(id);
  if (!packet.hostScope?.length || !packet.tenantIds?.length) throw new DashboardError("Prepare a fresh report before creating a ticket.");
  const db = await patchTicketDatabase(), client = await db.connect();
  try {
    await client.query("BEGIN");
    const current = (await client.query("SELECT revision FROM dashboard_source_connections WHERE source='crowdstrike' FOR SHARE")).rows[0];
    if (current?.revision !== revision) throw new DashboardError("CrowdStrike connection changed. Prepare a fresh request.", 409);
    await client.query(`INSERT INTO patch_ticket_requests(id,cve,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,tenant_ids,scope_hash)
      VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8::jsonb,$9) ON CONFLICT(id) DO NOTHING`,
      [id, packet.cve, actor, packet.collectedAt, revision, JSON.stringify(packet), packet.hostCount, JSON.stringify(packet.tenantIds), createHash("sha256").update(JSON.stringify([...packet.hostScope].sort())).digest("hex")]);
    await client.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,$2,'report.prepared')", [id, actor]);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  return id;
}
async function recoverInterruptedRequests() {
  const db = await patchTicketDatabase();
  await db.query(`UPDATE patch_ticket_requests SET state='uncertain',last_error='Creation was interrupted. Check the creation outcome before retrying.',updated_at=now()
    WHERE state='creating' AND started_at < now()-interval '3 minutes'`);
  await db.query(`UPDATE patch_ticket_requests SET attachment_state='pending',last_error='CSV attachment was interrupted. Retry the attachment check.',updated_at=now()
    WHERE attachment_state='uploading' AND attachment_started < now()-interval '3 minutes'`);
}
export async function listPatchTickets(cve?: string) {
  if (cve) cve = parsePatchInput({ cve }).cve;
  const db = await patchTicketDatabase(); await recoverInterruptedRequests();
  const rows = await db.query(`SELECT ${fields} FROM patch_ticket_requests ${cve ? "WHERE cve=$1" : ""} ORDER BY prepared_at DESC LIMIT 101`, cve ? [cve] : []);
  return { requests: rows.rows.slice(0, 100).map(summary), more: rows.rows.length > 100 };
}
export async function readPatchTicket(id: string, withPacket = false) {
  requestId(id); const db = await patchTicketDatabase(); await recoverInterruptedRequests();
  const row = (await db.query(`SELECT ${fields}${withPacket ? ",packet" : ""} FROM patch_ticket_requests WHERE id=$1`, [id])).rows[0];
  if (!row) throw new DashboardError("Patch request not found.", 404);
  return { request: summary(row), ...(withPacket ? { packet: row.packet as PatchRequest } : {}) };
}
const workers = new Set<string>();
function background(id: string, work: () => Promise<void>) {
  if (workers.has(id)) return;
  workers.add(id);
  void work().catch(() => console.error("[patch-tickets] Request processing interrupted; check its saved state.")).finally(() => workers.delete(id));
}

export async function createPatchTicket(id: string, value: unknown, actor: string) {
  requestId(id); const body = value as CWRecord;
  const routing = parseRouting(body?.routing);
  if (typeof body.title !== "string" || !body.title.trim() || body.title.length > 100 || typeof body.body !== "string" || !body.body.trim() || body.body.length > 200000) throw new DashboardError("Provide a ticket title of at most 100 characters and ticket contents of at most 200,000 characters.");
  const saved = await savedConnection(), db = await patchTicketDatabase(), client = await db.connect();
  let start = false;
  try {
    await client.query("BEGIN"); await client.query("SELECT pg_advisory_xact_lock(804205)");
    const row = (await client.query("SELECT * FROM patch_ticket_requests WHERE id=$1 FOR UPDATE", [id])).rows[0];
    if (!row) throw new DashboardError("Patch request not found.", 404);
    if (["creating", "uncertain", "created"].includes(row.state)) { await client.query("COMMIT"); return readPatchTicket(id); }
    if (row.tenant_ids.length !== 1) throw new DashboardError("This report spans multiple CrowdStrike tenants. Prepare a tenant-specific report before creating a customer ticket.");
    const cs = (await client.query("SELECT revision FROM dashboard_source_connections WHERE source='crowdstrike' FOR SHARE")).rows[0];
    if (cs?.revision !== row.crowdstrike_revision) throw new DashboardError("CrowdStrike connection changed. Prepare a fresh report before sending.", 409);
    const cw = (await client.query("SELECT revision FROM patch_connectwise_connection WHERE id=1 FOR SHARE")).rows[0];
    if (cw?.revision !== saved.revision || body.connectionRevision !== saved.revision) throw new DashboardError("ConnectWise connection changed. Reload its options before sending.", 409);
    const existing = (await client.query(`SELECT id,ticket_id FROM patch_ticket_requests WHERE cw_target=$1 AND cve=$2 AND company_id=$3 AND scope_hash=$4
      AND state IN ('creating','uncertain','created') AND closed=false AND id<>$5 LIMIT 1`, [saved.target, row.cve, routing.companyId, row.scope_hash, id])).rows[0];
    if (existing) throw new DashboardError(`This CVE and device scope already has ${existing.ticket_id ? `ticket #${existing.ticket_id}` : "a ticket request in progress"}. Open its saved request below.`, 409);
    await client.query(`UPDATE patch_ticket_requests SET state='creating',created_by=$2,cw_target=$3,cw_revision=$4,company_id=$5,routing=$6::jsonb,title=$7,body=$8,
      started_at=now(),updated_at=now(),last_error=NULL WHERE id=$1`, [id, actor, saved.target, saved.revision, routing.companyId, JSON.stringify(routing), body.title.trim(), body.body.trim()]);
    await client.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.requested')", [id, actor]);
    await client.query("COMMIT"); start = true;
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  if (start) background(id, () => runCreation(id));
  return readPatchTicket(id);
}
async function recordTicket(id: string, ticket: CWRecord, connection: ConnectWiseConnection) {
  if (!cwId(ticket?.id)) throw new CWRequestError("ConnectWise did not return a ticket number. Check the creation outcome.", true);
  const db = await patchTicketDatabase();
  await db.query(`UPDATE patch_ticket_requests SET state='created',ticket_id=$2,ticket_url=$3,ticket_status=$4,closed=$5,attachment_state='pending',last_error=NULL,updated_at=now() WHERE id=$1 AND ticket_id IS NULL`,
    [id, ticket.id, ticketUrl(connection, ticket.id), typeof ticket.status?.name === "string" ? ticket.status.name : "Created", ticket.closedFlag === true]);
}
async function runCreation(id: string) {
  const db = await patchTicketDatabase(); let writeStarted = false, ticketSaved = false;
  try {
    const row = (await db.query("SELECT * FROM patch_ticket_requests WHERE id=$1", [id])).rows[0];
    if (row?.state !== "creating") return;
    const saved = await savedConnection();
    if (saved.revision !== row.cw_revision || saved.target !== row.cw_target) throw new DashboardError("ConnectWise connection changed before sending. Review and submit again.");
    const labels = await validateCWRouting(saved.value, row.routing as TicketRouting);
    await db.query("UPDATE patch_ticket_requests SET labels=$2::jsonb,updated_at=now() WHERE id=$1", [id, JSON.stringify(labels)]);
    // Check again after routing reads, before the only ticket-creation POST.
    const current = await savedConnection();
    if (current.revision !== saved.revision) throw new DashboardError("ConnectWise connection changed before sending. Review and submit again.");
    writeStarted = true;
    const ticket = await cwRequest(saved.value, "/service/tickets", "POST", { summary: row.title, initialDescription: row.body, recordType: "ServiceTicket",
      board: { id: row.routing.boardId }, company: { id: row.routing.companyId }, status: { id: row.routing.statusId }, priority: { id: row.routing.priorityId },
      ...(row.routing.teamId ? { team: { id: row.routing.teamId } } : {}), externalXRef: `GMI-${id}` });
    await recordTicket(id, ticket, saved.value); ticketSaved = true;
    await db.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,$2,'ticket.created')", [id, row.created_by]);
    await attachCsv(id, row.created_by);
  } catch (error) {
    const message = error instanceof DashboardError ? error.message : "The request was interrupted. Check its saved state before retrying.";
    const uncertain = writeStarted && (!(error instanceof CWRequestError) || error.uncertain);
    // Never erase a returned ticket ID because uploading or auditing failed.
    await db.query(`UPDATE patch_ticket_requests SET state=CASE WHEN ticket_id IS NOT NULL THEN 'created' ELSE $2 END,
      last_error=$3,updated_at=now() WHERE id=$1`, [id, ticketSaved || uncertain ? "uncertain" : "failed", message]);
  }
}
async function attachCsv(id: string, actor: string) {
  const db = await patchTicketDatabase();
  const row = (await db.query(`UPDATE patch_ticket_requests SET attachment_state='uploading',attachment_started=now(),updated_at=now()
    WHERE id=$1 AND ticket_id IS NOT NULL AND attachment_state IN ('pending','not_started') RETURNING *`, [id])).rows[0];
  if (!row) return;
  try {
    const saved = await savedConnection();
    if (saved.target !== row.cw_target) throw new DashboardError("Connect the original ConnectWise account to attach this report.");
    const ticket = await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`);
    if (ticket.id !== row.ticket_id || ticket.company?.id !== row.company_id || ticket.externalXRef !== `GMI-${id}`) throw new DashboardError("The ticket's company or request reference changed. Review the ticket before attaching customer data.");
    const documentId = await uploadPatchCsv(saved.value, row.ticket_id, id, row.cve, (row.packet as PatchRequest).csv);
    await db.query("UPDATE patch_ticket_requests SET attachment_state='attached',document_id=$2,last_error=NULL,updated_at=now() WHERE id=$1", [id, documentId]);
    await db.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,$2,'csv.attached')", [id, actor]);
  } catch (error) {
    await db.query("UPDATE patch_ticket_requests SET attachment_state='pending',last_error=$2,updated_at=now() WHERE id=$1", [id, error instanceof DashboardError ? error.message : "CSV upload was interrupted. Retry the attachment check."]);
  }
}
export async function patchTicketAction(id: string, action: unknown, actor: string) {
  requestId(id); await recoverInterruptedRequests();
  const db = await patchTicketDatabase(), row = (await db.query("SELECT * FROM patch_ticket_requests WHERE id=$1", [id])).rows[0];
  if (!row) throw new DashboardError("Patch request not found.", 404);
  if (action === "retry-attachment") {
    if (!row.ticket_id) throw new DashboardError("Resolve the ticket creation outcome first.");
    background(id, () => attachCsv(id, actor));
    return readPatchTicket(id);
  }
  if (action !== "reconcile" && action !== "check-status") throw new DashboardError("Choose a supported ticket action.");
  const saved = await savedConnection();
  if (saved.target !== row.cw_target) throw new DashboardError("Connect the original ConnectWise account to check this request.");
  if (row.state === "creating") throw new DashboardError("Ticket creation is still in progress. Wait for it to finish.", 409);
  const ticket = row.ticket_id ? await cwRequest(saved.value, `/service/tickets/${row.ticket_id}`) : await findCWRequest(saved.value, `GMI-${id}`);
  if (!ticket) throw new DashboardError("No matching ticket is visible yet. Check ConnectWise and try this check again; another ticket has not been sent.", 409);
  if (ticket.company?.id !== row.company_id || ticket.externalXRef !== `GMI-${id}` || (row.ticket_id && ticket.id !== row.ticket_id)) throw new DashboardError("The ticket no longer matches this request's company and reference. Review it in ConnectWise.", 409);
  if (!row.ticket_id) await recordTicket(id, ticket, saved.value);
  await db.query("UPDATE patch_ticket_requests SET ticket_status=$2,closed=$3,last_error=NULL,updated_at=now() WHERE id=$1", [id, ticket.status?.name ?? "Unknown", ticket.closedFlag === true]);
  await db.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,$2,$3)", [id, actor, action === "reconcile" ? "ticket.reconciled" : "ticket.status.checked"]);
  return readPatchTicket(id);
}
export { automatedTicketBody };
