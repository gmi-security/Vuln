// Finds (and optionally closes) ConnectWise tickets that group-auto-create.ts
// opened for Atlas Healthcare Partners (CO-147284) before the 2026-10-08
// enrichment-gate fix -- i.e. tickets that went out on CrowdStrike's raw
// CVSS severity alone, with no finding_risk row (or no urgent one) behind
// them. This is a standalone audit/cleanup tool, not part of the running
// app: it is meant to be run by hand, once, by someone with both database
// and ConnectWise access, to deal with the backlog the old gate created.
//
// SAFE BY DEFAULT: with no flags, this only reads and prints a report --
// it makes zero ConnectWise calls and changes nothing. Closing tickets
// requires --close AND --yes, and is capped by --limit (default 5) so you
// can sanity-check a small batch before trusting it with the rest.
//
//   node scripts/audit-unenriched-auto-tickets.mjs
//   node scripts/audit-unenriched-auto-tickets.mjs --close --yes --limit 25
//
// Required env: DATABASE_URL (the application DB -- finding_risk lives
// here), and ELASTIC_VULN_DATABASE_URL if this instance uses a separate
// dashboard DB for patch_group_ticket_requests (same two pools the app
// itself resolves in lib/persist.ts/lib/elastic-dashboard-store.ts -- if
// ELASTIC_VULN_DATABASE_URL isn't set, DATABASE_URL is used for both,
// exactly like the app does).
//
// Required env for --close only: CW_ENDPOINT, CW_COMPANY_ID, CW_PUBLIC_KEY,
// CW_PRIVATE_KEY, CW_CLIENT_ID -- a ConnectWise API member's own
// credentials, NOT read from the app's saved (encrypted) connection, so
// this never needs the app's decryption key and its provenance is explicit
// in your shell history/env instead of implicit.

import pg from "pg";

const args = process.argv.slice(2);
const DO_CLOSE = args.includes("--close");
const CONFIRMED = args.includes("--yes");
const LIMIT = Number(args.find((a, i) => args[i - 1] === "--limit")) || 5;
const PILOT_COMPANY_ID = "CO-147284"; // ATLAS_REPORTING_COMPANY_ID, lib/reporting-direct-sources.ts
const ELIGIBLE_SWATH = 2; // must match lib/group-auto-create.ts's ELIGIBLE_SWATH

if (DO_CLOSE && !CONFIRMED) {
  throw new Error("--close requires --yes too. This closes real ConnectWise tickets -- run without --close first and review the report.");
}

const appUrl = process.env.DATABASE_URL;
if (!appUrl) throw new Error("DATABASE_URL is required.");
const dashboardUrl = process.env.ELASTIC_VULN_DATABASE_URL || appUrl;

const appPool = new pg.Pool({ connectionString: appUrl, ssl: { rejectUnauthorized: false }, max: 2, connectionTimeoutMillis: 8000 });
const dashboardPool = dashboardUrl === appUrl ? appPool : new pg.Pool({ connectionString: dashboardUrl, ssl: { rejectUnauthorized: false }, max: 2, connectionTimeoutMillis: 8000 });

async function findCandidates() {
  // Every still-open ticket auto-create actually sent to ConnectWise for the
  // pilot customer. AUTOMATED_ACTORS-style check isn't needed here -- we
  // want every auto-create ticket.requested audit entry regardless of what
  // happened to its priority afterward.
  const { rows: tickets } = await dashboardPool.query(`
    SELECT t.id, t.ticket_id, t.cves, t.created_at, t.updated_at
    FROM patch_group_ticket_requests t
    WHERE t.packet->>'appCompanyId' = $1 AND t.state = 'created' AND t.ticket_id IS NOT NULL AND t.closed = false
      AND EXISTS (SELECT 1 FROM patch_group_ticket_audit a WHERE a.request_id = t.id AND a.actor = 'auto-create' AND a.action = 'ticket.created')
    ORDER BY t.created_at ASC
  `, [PILOT_COMPANY_ID]);
  if (!tickets.length) return [];

  const out = [];
  for (const ticket of tickets) {
    if (!ticket.cves?.length) continue;
    const { rows } = await appPool.query(
      `SELECT min(effective_swath) AS swath FROM finding_risk
       WHERE tenant_key=$1 AND cve = ANY($2::text[]) AND source_open AND verification_status != 'verified_remediated'`,
      [PILOT_COMPANY_ID, ticket.cves],
    );
    const swath = rows[0]?.swath ?? null;
    if (swath != null && swath <= ELIGIBLE_SWATH) continue; // would still qualify under the new gate -- leave it alone
    out.push({ ...ticket, swath, reason: swath == null ? "never enriched" : `enriched but not urgent (Swath ${swath})` });
  }
  return out;
}

function cwAuth() {
  for (const key of ["CW_ENDPOINT", "CW_COMPANY_ID", "CW_PUBLIC_KEY", "CW_PRIVATE_KEY", "CW_CLIENT_ID"]) {
    if (!process.env[key]) throw new Error(`${key} is required for --close.`);
  }
  const endpoint = process.env.CW_ENDPOINT.replace(/\/$/, "");
  const auth = Buffer.from(`${process.env.CW_COMPANY_ID}+${process.env.CW_PUBLIC_KEY}:${process.env.CW_PRIVATE_KEY}`).toString("base64");
  return { endpoint, headers: { Authorization: `Basic ${auth}`, clientId: process.env.CW_CLIENT_ID, Accept: "application/json", "Content-Type": "application/json" } };
}

async function cwGet(auth, path) {
  const res = await fetch(`${auth.endpoint}${path}`, { headers: auth.headers });
  if (!res.ok) throw new Error(`ConnectWise GET ${path} -> HTTP ${res.status}`);
  return res.json();
}
async function cwPatch(auth, path, body) {
  const res = await fetch(`${auth.endpoint}${path}`, { method: "PATCH", headers: auth.headers, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`ConnectWise PATCH ${path} -> HTTP ${res.status}: ${await res.text().catch(() => "")}`);
  return res.json();
}
async function cwPost(auth, path, body) {
  const res = await fetch(`${auth.endpoint}${path}`, { method: "POST", headers: auth.headers, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`ConnectWise POST ${path} -> HTTP ${res.status}: ${await res.text().catch(() => "")}`);
  return res.json();
}

// Mirrors lib/connectwise-client.ts's cwDefaultClosedStatus, standalone.
async function closedStatusForBoard(auth, boardId) {
  const rows = await cwGet(auth, `/service/boards/${boardId}/statuses?pageSize=100`);
  const closed = rows.filter(r => r.id && r.name && !r.inactiveFlag && !r.inactive && !r.deletedFlag && (r.closedStatus || r.closedFlag));
  if (!closed.length) throw new Error(`Board ${boardId} has no closed status configured.`);
  return closed.find(r => r.defaultFlag) ?? closed[0];
}

async function main() {
  const candidates = await findCandidates();
  console.log(`${candidates.length} open auto-created ticket(s) for ${PILOT_COMPANY_ID} would NOT qualify under the new enrichment gate:\n`);
  for (const c of candidates) {
    console.log(`  #${c.ticket_id}  created ${new Date(c.created_at).toISOString()}  ${c.reason}  cves=${c.cves.join(",")}`);
  }
  if (!candidates.length) { console.log("Nothing to do."); return; }
  if (!DO_CLOSE) {
    console.log(`\nDry run only -- re-run with --close --yes --limit N to actually close up to N of these in ConnectWise.`);
    return;
  }

  const auth = cwAuth();
  const batch = candidates.slice(0, LIMIT);
  console.log(`\nClosing ${batch.length} of ${candidates.length} (--limit ${LIMIT})...`);
  const closedStatusByBoard = new Map();
  for (const c of batch) {
    try {
      const ticket = await cwGet(auth, `/service/tickets/${c.ticket_id}`);
      if (ticket.closedFlag) { console.log(`  #${c.ticket_id}: already closed, skipping`); continue; }
      const boardId = ticket.board?.id;
      if (!boardId) throw new Error("ticket has no board id");
      let status = closedStatusByBoard.get(boardId);
      if (!status) { status = await closedStatusForBoard(auth, boardId); closedStatusByBoard.set(boardId, status); }
      await cwPost(auth, `/service/tickets/${c.ticket_id}/notes`, {
        text: `Closed by audit-unenriched-auto-tickets.mjs on ${new Date().toISOString()}: this ticket was auto-created from CrowdStrike's raw CVSS severity before group-auto-create.ts required real finding_risk enrichment data (2026-10-08 fix). Reason: ${c.reason}. Re-open or re-ticket if this finding is confirmed to need action.`,
        detailDescriptionFlag: true,
      });
      await cwPatch(auth, `/service/tickets/${c.ticket_id}`, [{ op: "replace", path: "status/id", value: status.id }]);
      console.log(`  #${c.ticket_id}: closed (status "${status.name}")`);
    } catch (err) {
      console.log(`  #${c.ticket_id}: FAILED -- ${err instanceof Error ? err.message : err}`);
    }
  }
}

try {
  await main();
} finally {
  await appPool.end();
  if (dashboardPool !== appPool) await dashboardPool.end();
}
