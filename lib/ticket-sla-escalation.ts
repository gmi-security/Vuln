import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { cwPrioritiesBySort, cwRequest, type ConnectWiseConnection, type CWOption } from "./connectwise-client";
import { runWithConcurrency } from "./ticket-status-sync";
import { elasticVulnEnabled } from "./elastic-vuln-server";

// An open ConnectWise ticket that just sits there without closing is failing
// its SLA the same way the "Age" badge on the ticket tracker already flags
// it (14+ days open = "overdue" there too). Rather than only flagging it,
// this bumps the ticket one ConnectWise priority level more urgent for every
// full interval it stays open and unresolved, so a stalled ticket keeps
// getting louder inside ConnectWise itself -- not just in our own UI.
const ESCALATION_INTERVAL_DAYS = 14;

type EscalationCounts = { checked: number; escalated: number; errors: number };
type Row = { id: string; ticket_id: number; prepared_at: string | Date; ticket_priority_id: number | null; ticket_sla_escalations: number };

export async function escalateTable(
  db: Awaited<ReturnType<typeof patchTicketDatabase>>,
  table: "patch_ticket_requests" | "patch_group_ticket_requests",
  target: string,
  connection: ConnectWiseConnection,
  priorities: CWOption[],
): Promise<EscalationCounts> {
  const rows = (await db.query(
    `SELECT id, ticket_id, prepared_at, ticket_priority_id, ticket_sla_escalations FROM ${table}
      WHERE state='created' AND closed=false AND ticket_id IS NOT NULL AND cw_target=$1`,
    [target],
  )).rows as Row[];
  if (!rows.length || !priorities.length) return { checked: rows.length, escalated: 0, errors: 0 };
  const due = rows.filter((row) => {
    const ageDays = Math.floor((Date.now() - new Date(row.prepared_at).getTime()) / 86_400_000);
    return Math.floor(ageDays / ESCALATION_INTERVAL_DAYS) > row.ticket_sla_escalations;
  });
  let escalated = 0, errors = 0;
  await runWithConcurrency(due, 5, async (row) => {
    try {
      const nextTier = row.ticket_sla_escalations + 1;
      // priorities is sorted most-urgent-first; an unrecognized current
      // priority falls back to the least-urgent slot, the safe assumption.
      let index = priorities.findIndex((p) => p.id === row.ticket_priority_id);
      if (index === -1) index = priorities.length - 1;
      if (index > 0) {
        const next = priorities[index - 1];
        await cwRequest(connection, `/service/tickets/${row.ticket_id}`, "PATCH", [{ op: "replace", path: "priority/id", value: next.id }]);
        await db.query(
          `UPDATE ${table} SET ticket_priority_id=$2, ticket_priority_name=$3, ticket_sla_escalations=$4, last_error=NULL, updated_at=now() WHERE id=$1`,
          [row.id, next.id, next.name, nextTier],
        );
        const auditTable = table === "patch_ticket_requests" ? "patch_ticket_audit" : "patch_group_ticket_audit";
        await db.query(`INSERT INTO ${auditTable}(request_id,actor,action) VALUES($1,'sla-escalation','ticket.priority.escalated')`, [row.id]);
        escalated++;
      } else {
        // Already at the most urgent priority ConnectWise offers -- nothing
        // left to bump. Record the tier so this ticket stops being rechecked
        // every pass.
        await db.query(`UPDATE ${table} SET ticket_sla_escalations=$2, updated_at=now() WHERE id=$1`, [row.id, nextTier]);
      }
    } catch {
      errors++; // one ticket failing to escalate (deleted, permissions) must not block the rest
    }
  });
  return { checked: rows.length, escalated, errors };
}

export async function escalateOverdueTickets(): Promise<EscalationCounts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, escalated: 0, errors: 0 };
  const db = await patchTicketDatabase();
  const priorities = await cwPrioritiesBySort(saved.value).catch(() => []);
  const [single, group] = await Promise.all([
    escalateTable(db, "patch_ticket_requests", saved.target, saved.value, priorities),
    escalateTable(db, "patch_group_ticket_requests", saved.target, saved.value, priorities),
  ]);
  return { checked: single.checked + group.checked, escalated: single.escalated + group.escalated, errors: single.errors + group.errors };
}

const runtime = globalThis as typeof globalThis & { __ticketSlaEscalation?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__ticketSlaEscalation ??= {};

export function startTicketSlaEscalationScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = escalateOverdueTickets().then(
      () => {},
      (err) => console.error("[ticket-sla-escalation] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
