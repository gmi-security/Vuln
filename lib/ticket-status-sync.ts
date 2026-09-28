import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { cwId, cwRequest, type ConnectWiseConnection } from "./connectwise-client";
import { elasticVulnEnabled } from "./elastic-vuln-server";

// Ticket status/closed only ever got refreshed when a human opened a
// specific ticket and clicked "check status" — a ticket cut from the
// dashboard and never revisited again just sat there showing whatever it
// looked like at creation, even after it closed in ConnectWise weeks later.
// This polls every open, previously-created ticket on a schedule so our own
// tracker and reporting stay in sync with ConnectWise without anyone having
// to click into each one by hand.

export async function runWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker() {
    for (let i = next++; i < items.length; i = next++) results[i] = await fn(items[i]);
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

type SyncCounts = { checked: number; updated: number; errors: number };

export async function syncTable(
  db: Awaited<ReturnType<typeof patchTicketDatabase>>,
  table: "patch_ticket_requests" | "patch_group_ticket_requests",
  target: string,
  connection: ConnectWiseConnection,
): Promise<SyncCounts> {
  const rows = (await db.query(
    `SELECT id, ticket_id FROM ${table} WHERE state='created' AND closed=false AND ticket_id IS NOT NULL AND cw_target=$1`,
    [target],
  )).rows as { id: string; ticket_id: number }[];
  if (!rows.length) return { checked: 0, updated: 0, errors: 0 };
  let updated = 0, errors = 0;
  await runWithConcurrency(rows, 5, async (row) => {
    try {
      const ticket = await cwRequest(connection, `/service/tickets/${row.ticket_id}`);
      const status = typeof ticket?.status?.name === "string" ? ticket.status.name : "Unknown";
      const closed = ticket?.closedFlag === true;
      const priorityId = cwId(ticket?.priority?.id) ? ticket.priority.id : null;
      const priorityName = typeof ticket?.priority?.name === "string" ? ticket.priority.name : null;
      const result = await db.query(
        `UPDATE ${table} SET ticket_status=$2, closed=$3, ticket_priority_id=$4, ticket_priority_name=$5, updated_at=now() WHERE id=$1
          AND (ticket_status IS DISTINCT FROM $2 OR closed IS DISTINCT FROM $3 OR ticket_priority_id IS DISTINCT FROM $4 OR ticket_priority_name IS DISTINCT FROM $5)`,
        [row.id, status, closed, priorityId, priorityName],
      );
      if (result.rowCount) {
        updated++;
        const auditTable = table === "patch_ticket_requests" ? "patch_ticket_audit" : "patch_group_ticket_audit";
        await db.query(`INSERT INTO ${auditTable}(request_id,actor,action) VALUES($1,'automatic sync','ticket.status.synced')`, [row.id]);
      }
    } catch {
      errors++; // A single ticket's lookup failing (deleted, permissions changed) must not block the rest.
    }
  });
  return { checked: rows.length, updated, errors };
}

export async function syncTicketStatuses(): Promise<SyncCounts> {
  const saved = await savedConnection().catch(() => null);
  if (!saved) return { checked: 0, updated: 0, errors: 0 };
  const db = await patchTicketDatabase();
  const [single, group] = await Promise.all([
    syncTable(db, "patch_ticket_requests", saved.target, saved.value),
    syncTable(db, "patch_group_ticket_requests", saved.target, saved.value),
  ]);
  return { checked: single.checked + group.checked, updated: single.updated + group.updated, errors: single.errors + group.errors };
}

const runtime = globalThis as typeof globalThis & { __ticketStatusSync?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__ticketStatusSync ??= {};

export function startTicketStatusSyncScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  const trigger = () => {
    if (state.working) return;
    state.working = syncTicketStatuses().then(
      () => {},
      (err) => console.error("[ticket-status-sync] Could not complete:", err instanceof Error ? err.message : err),
    ).finally(() => { state.working = undefined; });
  };
  state.timer = setInterval(trigger, 15 * 60_000);
  state.timer.unref();
  trigger();
}
