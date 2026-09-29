import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { createGroupTicket, readGroupTicket, reviewGroupTicket, setGroupTicketPriority } from "./patch-group-ticket-store";
import { runWithConcurrency } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DashboardError } from "./elastic-dashboard";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { cwPrioritiesBySort } from "./connectwise-client";
import { targetPriorityFor } from "./group-ticket-priority";

// Critical/High severity remediations skip the human review queue and go
// straight to a ConnectWise ticket -- always through the consolidated group
// format, never the single-CVE path. This only fires for a customer once a
// human has manually created at least one ticket for them: that's what
// teaches patch_customer_routing which ConnectWise company/board/team is
// correct (see the routing-learning step in runCreation, patch-group-ticket-
// store.ts). No mapping yet means no guess -- the draft is left for a human,
// same as before. Low/Medium/Low-confidence severity is never touched here.
const ACTOR = "auto-create";
// Pilot scope: only this customer, by explicit request, while auto-create is
// validated. Expand PILOT_COMPANY_IDS once it's proven out.
const PILOT_COMPANY_IDS = new Set([ATLAS_REPORTING_COMPANY_ID]);

type Counts = { checked: number; created: number; errors: number };

// Ticket creation is async (runCreation runs in the background); this polls
// the draft's own row for a confirmed ticket_id before setting priority,
// rather than guessing at timing. Gives up (not an error -- the ticket
// itself may still be fine) if it never lands within the window.
async function waitForTicketId(id: string, timeoutMs = 60_000): Promise<number | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { request } = await readGroupTicket(id);
    if (request.ticketId) return request.ticketId;
    if (!["prepared", "creating"].includes(request.state)) return null; // failed/uncertain -- stop waiting
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return null;
}

export async function autoCreateHighSeverityTickets(): Promise<Counts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, created: 0, errors: 0 };
  const db = await patchTicketDatabase();
  // Only the newest pending draft per remediation+tenant(+customer) -- the
  // same ranking group-draft-dedup.ts uses to decide what's stale. Without
  // this, a slower dedup sweep tick could still be racing to dismiss an
  // older duplicate at the same moment this auto-creates it.
  const rows = (await db.query(`
    WITH ranked AS (
      SELECT id, packet->>'appCompanyId' AS app_company_id, worst_severity, ROW_NUMBER() OVER (
        PARTITION BY remediation_id, tenant_id, packet->>'appCompanyId' ORDER BY prepared_at DESC
      ) AS rn
      FROM patch_group_ticket_requests
      WHERE state='prepared' AND review_state='pending' AND worst_severity IN ('Critical','High')
    )
    SELECT id, app_company_id, worst_severity FROM ranked WHERE rn = 1
  `)).rows as { id: string; app_company_id: string | null; worst_severity: "Critical" | "High" }[];
  if (!rows.length) return { checked: 0, created: 0, errors: 0 };
  const routings = (await db.query("SELECT app_company_id, company_id, board_id, team_id FROM patch_customer_routing"))
    .rows as { app_company_id: string; company_id: number; board_id: number; team_id: number | null }[];
  const routingByCompany = new Map(routings.map((r) => [r.app_company_id, r]));
  // Most-urgent-first; fetched once and reused for every ticket this pass.
  // Missing/unreachable never blocks ticket creation -- it just means the
  // priority stays whatever the board's default is, same as before this
  // existed, rather than failing the whole thing.
  const priorities = await cwPrioritiesBySort(saved.value).catch(() => []);
  let created = 0, errors = 0;
  await runWithConcurrency(rows, 3, async (row) => {
    if (!row.app_company_id || !PILOT_COMPANY_IDS.has(row.app_company_id)) return; // outside the pilot scope
    const routing = routingByCompany.get(row.app_company_id);
    if (!routing) return; // no known-good routing for this customer yet -- leave it for a human
    try {
      await reviewGroupTicket(row.id, "approve", ACTOR);
      const read = await readGroupTicket(row.id, true);
      if (!read.group) throw new DashboardError("Prepared consolidation is missing its packet.");
      await createGroupTicket(row.id, {
        routing: { companyId: routing.company_id, boardId: routing.board_id, ...(routing.team_id ? { teamId: routing.team_id } : {}) },
        title: read.group.ticketTitle, body: read.group.ticketBody, connectionRevision: saved.revision,
      }, ACTOR);
      created++;
      // The ticket should assert its own severity immediately, not wait
      // days for SLA escalation to notice. Critical -> the top priority;
      // High -> the next one down. Never lets a priority-setting problem
      // undo an otherwise-successful ticket creation.
      const target = targetPriorityFor(row.worst_severity, priorities);
      if (target) {
        const ticketId = await waitForTicketId(row.id);
        if (ticketId) {
          // A failure here used to vanish silently -- a real Critical
          // ticket could sit at the board's default priority indefinitely
          // with nothing recorded anywhere to say why. backfillTicketPriority
          // will retry it on the next pass (no ticket.priority.changed audit
          // means it never counts as already handled), but the reason for
          // the first failure is worth keeping visible in the meantime.
          await setGroupTicketPriority(row.id, target.id, ACTOR).catch(async (err) => {
            const message = err instanceof Error ? err.message : String(err);
            await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
              [row.id, `Ticket created, but asserting ${row.worst_severity} priority failed: ${message}`]).catch(() => {});
          });
        } else {
          await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
            [row.id, `Ticket created, but its ticket_id didn't appear within 60s to assert ${row.worst_severity} priority. The next priority backfill pass will retry.`]).catch(() => {});
        }
      }
    } catch {
      errors++; // one draft failing (routing went stale, connection changed) must not block the rest
    }
  });
  return { checked: rows.length, created, errors };
}

const runtime = globalThis as typeof globalThis & { __groupAutoCreate?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__groupAutoCreate ??= {};

export function startGroupAutoCreateScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = autoCreateHighSeverityTickets().then(
      () => {},
      (err) => console.error("[group-auto-create] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
