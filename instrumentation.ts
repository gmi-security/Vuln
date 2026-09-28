// Next.js instrumentation hook: runs once when the server boots. Kicking off
// hydration here (instead of on the first request) starts the in-process
// scheduler — auto-sync, daily metrics snapshots, monthly reports — from
// boot, so a quiet deployment still syncs and accumulates trend data.
//
// IMPORTANT: register() must NOT await hydration. Next.js blocks server
// startup until register resolves, and loading a multi-hundred-MB snapshot
// can outlast the platform health-check window — the container gets killed
// mid-boot and the app crash-loops. Fire and forget; requests that arrive
// before hydration finishes await ensureHydrated() themselves.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { startElasticDashboardScheduler } = await import("@/lib/elastic-dashboard-store");
  startElasticDashboardScheduler();
  const { startDashboardJobWorker } = await import("@/lib/elastic-dashboard-jobs");
  startDashboardJobWorker();
  const { ensureHydrated } = await import("@/lib/store");
  void ensureHydrated().catch((err) => {
    console.error("[instrumentation] boot hydration failed:", err);
  });
  const { startReportingQueueScheduler } = await import("@/lib/reporting-queue");
  startReportingQueueScheduler();
  const { startTicketStatusSyncScheduler } = await import("@/lib/ticket-status-sync");
  startTicketStatusSyncScheduler();
  const { startTicketSlaEscalationScheduler } = await import("@/lib/ticket-sla-escalation");
  startTicketSlaEscalationScheduler();
  const { startGroupDraftDedupScheduler } = await import("@/lib/group-draft-dedup");
  startGroupDraftDedupScheduler();
  // Backfills worst_severity and appCompanyId on drafts prepared before those
  // existed / before ATLAS_CROWDSTRIKE_TENANT_IDS was configured, then starts
  // auto-create -- sequenced so its first pass (which filters on both) already
  // sees the real values for the existing backlog, not just newly-prepared
  // drafts. Backfill errors never block the scheduler from starting;
  // register() itself is never blocked either.
  const { backfillWorstSeverity } = await import("@/lib/group-severity-backfill");
  const { backfillAppCompanyId } = await import("@/lib/group-company-backfill");
  const backfill = Promise.all([
    backfillWorstSeverity().catch((err) => { console.error("[instrumentation] worst_severity backfill failed:", err); }),
    backfillAppCompanyId().catch((err) => { console.error("[instrumentation] appCompanyId backfill failed:", err); }),
  ]);
  const { startGroupAutoCreateScheduler } = await import("@/lib/group-auto-create");
  void backfill.then(() => startGroupAutoCreateScheduler());
}
