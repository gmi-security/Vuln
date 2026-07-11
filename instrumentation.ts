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
  const { ensureHydrated } = await import("@/lib/store");
  void ensureHydrated().catch((err) => {
    console.error("[instrumentation] boot hydration failed:", err);
  });
}
