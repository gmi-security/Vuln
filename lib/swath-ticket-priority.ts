import { patchTicketDatabase } from "./patch-ticket-store";
import { setGroupTicketPriority } from "./patch-group-ticket-store";
import { cwPrioritiesBySort } from "./connectwise-client";
import { savedConnection } from "./patch-ticket-store";
import { targetPriorityForSwath } from "./group-ticket-priority";
import { riskScoringDatabase } from "./risk-scoring-store";

const ACTOR = "risk-engine";
// Automated actors this pass is allowed to reconcile priority over. A real
// analyst's name/email here means a human deliberately chose the priority --
// same "never overwrite an already-learned/human-set value" rule the rest
// of this codebase's priority automation follows (see
// group-priority-backfill.ts). Extend this set if a new automated actor is
// added; anyone not in it is treated as human.
const AUTOMATED_ACTORS = new Set(["auto-create", "backfill-priority", ACTOR]);

export type SwathPriorityResult = { checked: number; updated: number; errors: number };

// Ticket priority should track effective Swath, per the RBVM spec -- this
// is deliberately a SEPARATE pass from auto-create's creation-time priority
// assertion (group-auto-create.ts) and the old severity-based backfill
// (group-priority-backfill.ts), not a rewrite of either: those already work
// and are well-tested, and Swath data for a ticket's CVEs may not exist yet
// at the moment the ticket is created (finding_risk is populated by its own
// scheduler). This pass reconciles priority to Swath whenever it runs,
// as long as no human has ever touched that ticket's priority.
export async function reconcileTicketPriorityToSwath(): Promise<SwathPriorityResult> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, updated: 0, errors: 0 };
  const cwDb = await patchTicketDatabase();
  const tickets = (await cwDb.query(`
    SELECT t.id, t.tenant_id, t.cves, t.ticket_priority_id FROM patch_group_ticket_requests t
    WHERE t.state='created' AND t.ticket_id IS NOT NULL AND t.closed=false
      AND NOT EXISTS (
        SELECT 1 FROM patch_group_ticket_audit a WHERE a.request_id=t.id AND a.action='ticket.priority.changed'
          AND a.actor NOT IN (${Array.from(AUTOMATED_ACTORS).map((_, i) => `$${i + 1}`).join(",")})
      )
  `, Array.from(AUTOMATED_ACTORS))).rows as { id: string; tenant_id: string; cves: string[]; ticket_priority_id: number | null }[];
  if (!tickets.length) return { checked: 0, updated: 0, errors: 0 };

  const priorities = await cwPrioritiesBySort(saved.value).catch(() => []);
  if (!priorities.length) return { checked: tickets.length, updated: 0, errors: 0 };

  const riskDb = await riskScoringDatabase();
  let updated = 0, errors = 0;
  for (const ticket of tickets) {
    try {
      if (!ticket.cves?.length) continue;
      const row = (await riskDb.query(
        "SELECT min(effective_swath) AS swath FROM finding_risk WHERE tenant_key=$1 AND cve = ANY($2::text[])",
        [ticket.tenant_id, ticket.cves],
      )).rows[0] as { swath: number | null };
      if (row.swath == null) continue; // no risk data yet for this ticket's CVEs -- nothing to reconcile against
      const target = targetPriorityForSwath(row.swath as 1 | 2 | 3 | 4, priorities);
      if (!target || target.id === ticket.ticket_priority_id) continue;
      await setGroupTicketPriority(ticket.id, target.id, ACTOR);
      updated++;
    } catch {
      errors++; // one ticket's ConnectWise call failing must not block the rest
    }
  }
  return { checked: tickets.length, updated, errors };
}
