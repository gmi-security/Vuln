import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { createGroupTicket, readGroupTicket, reviewGroupTicket } from "./patch-group-ticket-store";
import { runWithConcurrency } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";
import { DashboardError } from "./elastic-dashboard";

// Critical/High severity remediations skip the human review queue and go
// straight to a ConnectWise ticket -- always through the consolidated group
// format, never the single-CVE path. This only fires for a customer once a
// human has manually created at least one ticket for them: that's what
// teaches patch_customer_routing which ConnectWise company/board/team is
// correct (see the routing-learning step in runCreation, patch-group-ticket-
// store.ts). No mapping yet means no guess -- the draft is left for a human,
// same as before. Low/Medium/Low-confidence severity is never touched here.
const ACTOR = "auto-create";

type Counts = { checked: number; created: number; errors: number };

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
      SELECT id, packet->>'appCompanyId' AS app_company_id, ROW_NUMBER() OVER (
        PARTITION BY remediation_id, tenant_id, packet->>'appCompanyId' ORDER BY prepared_at DESC
      ) AS rn
      FROM patch_group_ticket_requests
      WHERE state='prepared' AND review_state='pending' AND worst_severity IN ('Critical','High')
    )
    SELECT id, app_company_id FROM ranked WHERE rn = 1
  `)).rows as { id: string; app_company_id: string | null }[];
  if (!rows.length) return { checked: 0, created: 0, errors: 0 };
  const routings = (await db.query("SELECT app_company_id, company_id, board_id, team_id FROM patch_customer_routing"))
    .rows as { app_company_id: string; company_id: number; board_id: number; team_id: number | null }[];
  const routingByCompany = new Map(routings.map((r) => [r.app_company_id, r]));
  let created = 0, errors = 0;
  await runWithConcurrency(rows, 3, async (row) => {
    const routing = row.app_company_id ? routingByCompany.get(row.app_company_id) : undefined;
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
