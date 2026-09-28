import { patchTicketDatabase } from "./patch-ticket-store";
import { worstSeverityOf } from "./vuln-sla";
import type { PatchGroup } from "./patch-request";

// worst_severity is computed and stored at persist time (see
// persistPreparedGroups) as of the commit that added the column -- rows
// prepared before that have it NULL, which makes them invisible to anything
// keyed on severity: the Age badges' SLA threshold, auto-escalation, and
// auto-create all fall back to a generic default for NULL rather than their
// real severity. The data to compute it was already there all along, in
// each row's own stored packet (reviewRows carries a severity per CVE/row).
// One-shot backfill, safe to call repeatedly -- it only ever touches rows
// still missing the column.
export async function backfillWorstSeverity(): Promise<{ updated: number }> {
  const db = await patchTicketDatabase();
  const rows = (await db.query("SELECT id, packet FROM patch_group_ticket_requests WHERE worst_severity IS NULL"))
    .rows as { id: string; packet: PatchGroup }[];
  let updated = 0;
  for (const row of rows) {
    const worst = worstSeverityOf(row.packet.reviewRows ?? []);
    if (!worst) continue; // genuinely no severity data on this row -- leave it NULL, same as new rows would be
    await db.query("UPDATE patch_group_ticket_requests SET worst_severity=$2 WHERE id=$1", [row.id, worst]);
    updated++;
  }
  return { updated };
}
