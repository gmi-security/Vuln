// Next.js instrumentation hook: runs once when the server boots. Hydrating
// the store here (instead of on the first request) starts the in-process
// scheduler — auto-sync, daily metrics snapshots, monthly reports — from
// boot, so a quiet deployment still syncs and accumulates trend data.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { ensureHydrated } = await import("@/lib/store");
  await ensureHydrated();
}
