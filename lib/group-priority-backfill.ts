import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { setGroupTicketPriority } from "./patch-group-ticket-store";
import { runWithConcurrency } from "./ticket-status-sync";
import { cwPrioritiesBySort } from "./connectwise-client";
import { ATLAS_REPORTING_COMPANY_ID } from "./reporting-direct-sources";
import { targetPriorityFor } from "./group-ticket-priority";

const ACTOR = "backfill-priority";
// Same pilot scope as group-auto-create.ts -- this only catches up tickets
// that auto-create itself would have touched, had priority-setting existed
// when they were created.
const PILOT_COMPANY_IDS = [ATLAS_REPORTING_COMPANY_ID];

// One-time catch-up for Critical/High tickets already sitting in ConnectWise
// at its board default priority, created before auto-create started setting
// priority explicitly (see group-auto-create.ts). Skips anything that already
// has a 'ticket.priority.changed' audit entry -- that means either this
// backfill already covered it on an earlier pass, or a human deliberately
// chose a priority through the app -- so it never overwrites a decision
// someone already made. Safe to run repeatedly: nothing left to catch up
// means no calls at all.
export async function backfillTicketPriority(): Promise<{ checked: number; updated: number; errors: number }> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, updated: 0, errors: 0 };
  const db = await patchTicketDatabase();
  const rows = (await db.query(`
    SELECT g.id, g.worst_severity FROM patch_group_ticket_requests g
    WHERE g.state='created' AND g.ticket_id IS NOT NULL AND g.worst_severity IN ('Critical','High')
      AND g.packet->>'appCompanyId' = ANY($1::text[])
      AND NOT EXISTS (
        SELECT 1 FROM patch_group_ticket_audit a WHERE a.request_id = g.id AND a.action = 'ticket.priority.changed'
      )
  `, [PILOT_COMPANY_IDS])).rows as { id: string; worst_severity: "Critical" | "High" }[];
  if (!rows.length) return { checked: 0, updated: 0, errors: 0 };
  const priorities = await cwPrioritiesBySort(saved.value).catch(() => []);
  if (!priorities.length) return { checked: rows.length, updated: 0, errors: 0 };
  let updated = 0, errors = 0;
  await runWithConcurrency(rows, 3, async (row) => {
    const target = targetPriorityFor(row.worst_severity, priorities);
    if (!target) return;
    try {
      await setGroupTicketPriority(row.id, target.id, ACTOR);
      updated++;
    } catch (err) {
      errors++; // one ticket's connection mismatch or ConnectWise rejection must not block the rest
      const message = err instanceof Error ? err.message : String(err);
      await db.query("UPDATE patch_group_ticket_requests SET last_error=$2,updated_at=now() WHERE id=$1",
        [row.id, `Priority backfill failed to set ${row.worst_severity} priority: ${message}`]).catch(() => {});
    }
  });
  return { checked: rows.length, updated, errors };
}
