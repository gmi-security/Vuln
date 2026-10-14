// Every one of these schedulers fires its first pass IMMEDIATELY when
// started (not just on its recurring interval) -- see the "trigger()" call
// right after each lib/*.ts's own setInterval(). Starting all ~9 of them in
// one tight synchronous burst at boot means every restart (a deploy, or an
// ops `pm2 restart`) launches CrowdStrike verification calls, ConnectWise
// polling, and a full Spotlight risk-rescore -- which alone can be millions
// of rows for a large tenant -- all at once, competing for the same capped
// DB connection pool at the exact moment the app is also absorbing a
// post-restart traffic burst. That's a real incident, not a hypothetical:
// a restart produced a multi-second DB timeout on an ordinary page load
// while risk-refresh alone was mid-pass.
//
// Staggering each scheduler's START (not its recurring interval -- those
// stay as each file defines them) spreads the first-boot load out over a
// few minutes instead of one instant, without changing steady-state
// behavior at all once every scheduler has had its first run.
// start may itself kick off further async work (a dynamic import, a
// backfill chain) without awaiting it here -- same fire-and-forget posture
// as the rest of this file. Both a synchronous throw and an async rejection
// are caught so a failed dynamic import never becomes an unhandled
// rejection; either way it's logged and every other staggered start is
// unaffected.
function delayedStart(label: string, ms: number, start: () => void | Promise<void>): void {
  setTimeout(() => {
    try {
      void Promise.resolve(start()).catch((err) => {
        console.error(`[instrumentation] ${label} failed to start:`, err);
      });
    } catch (err) {
      console.error(`[instrumentation] ${label} failed to start:`, err);
    }
  }, ms).unref();
}

// Next.js instrumentation hook: runs once when the server boots. Kicking off
// hydration here (instead of on the first request) starts the in-process
// scheduler — auto-sync, daily metrics snapshots, monthly reports — from
// boot, so a quiet deployment still syncs and accumulates trend data.
//
// IMPORTANT: register() must NOT await hydration. Next.js blocks server
// startup until register resolves, and loading a multi-hundred-MB snapshot
// can outlast the platform health-check window — the container gets killed
// mid-boot and the app crash-loops. Fire and forget; requests that arrive
// before hydration finishes await ensureHydrated() themselves. Hydration
// itself is the one thing here that stays un-staggered -- every request
// needs it, so delaying it would just move the pain to the first requests
// after boot instead of removing it.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { ensureHydrated } = await import("@/lib/store");
  void ensureHydrated().catch((err) => {
    console.error("[instrumentation] boot hydration failed:", err);
  });

  if (process.env.VULN_RUNTIME_ROLE === "web") return;

  delayedStart("elastic dashboard scheduler", 15_000, () =>
    import("@/lib/elastic-dashboard-store").then((m) => m.startElasticDashboardScheduler()),
  );
  delayedStart("elastic dashboard job worker", 30_000, () =>
    import("@/lib/elastic-dashboard-jobs").then((m) => m.startDashboardJobWorker()),
  );
  // Tickets are prepared from a CVE and explicitly approved in the Tickets
  // view. Background processing only reads their ConnectWise status; it must
  // never prepare, approve, send, reprioritize or reopen tickets.
  delayedStart("ticket status sync scheduler", 60_000, () =>
    import("@/lib/ticket-status-sync").then((m) => m.startTicketStatusSyncScheduler()),
  );

  // Risk-Based Vulnerability Management: refreshes CISA KEV/EPSS for CVEs
  // actually present in each tenant's current Spotlight generation, then
  // recomputes finding_risk (risk score, Swath, verification status). See
  // lib/risk-refresh-scheduler.ts. Heaviest job here by far (can be
  // millions of rows for a large tenant) -- starts last and latest, well
  // after hydration and every other scheduler's first pass has cleared.
  delayedStart("risk refresh scheduler", 240_000, () =>
    import("@/lib/risk-refresh-scheduler").then((m) => m.startRiskRefreshScheduler()),
  );
  delayedStart("Defender customer import worker", 300_000, () =>
    import("@/lib/defender-worker").then((m) => m.startDefenderWorker()),
  );
}
