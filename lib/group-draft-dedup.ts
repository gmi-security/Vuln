import { patchTicketDatabase } from "./patch-ticket-store";
import { elasticVulnEnabled } from "./elastic-vuln-server";

// persistPreparedGroups already dismisses a stale pending draft the instant a
// fresher one for the same remediation+tenant(+customer) is persisted -- but
// that only guards new persists. It doesn't retroactively clean up drafts
// that already piled up before that existed, and it's cheap enough to run as
// an ongoing safety net regardless. This does the same thing in bulk: for
// every remediation+tenant(+customer) group with more than one still-*pending*
// draft, keep only the most recently prepared one and dismiss the rest.
// Never touches an already-*approved* draft -- that's a human decision this
// must not override. Dismissed drafts stay visible and reopenable.
export async function sweepSupersededGroupDrafts(): Promise<{ dismissed: number }> {
  const db = await patchTicketDatabase();
  const rows = await db.query(`
    WITH ranked AS (
      SELECT id, ROW_NUMBER() OVER (
        PARTITION BY remediation_id, tenant_id, packet->>'appCompanyId'
        ORDER BY prepared_at DESC
      ) AS rn
      FROM patch_group_ticket_requests
      WHERE state='prepared' AND review_state='pending'
    )
    UPDATE patch_group_ticket_requests SET review_state='dismissed', reviewed_by=$1, reviewed_at=now(), updated_at=now()
    WHERE id IN (SELECT id FROM ranked WHERE rn > 1)
    RETURNING id`, ["auto-dedup"]);
  for (const row of rows.rows as { id: string }[]) {
    await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,$2,'group.dismissed.superseded')", [row.id, "auto-dedup"]);
  }
  return { dismissed: rows.rowCount ?? 0 };
}

const runtime = globalThis as typeof globalThis & { __groupDraftDedup?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__groupDraftDedup ??= {};

export function startGroupDraftDedupScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = sweepSupersededGroupDrafts().then(
      () => {},
      (err) => console.error("[group-draft-dedup] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
