import { createDefenderClient, DefenderError, normalizeDefenderRecord } from "./defender-client";
import { defenderStore, type DefenderRun } from "./defender-store";

export async function importDefenderRun(run: DefenderRun, store = defenderStore(), clientFactory = createDefenderClient) {
  try {
    const connection = await store.connection(run.company_id);
    if (!connection || connection.revision !== run.revision) throw new DefenderError("Connection changed before import started. Retry Sync now.");
    const client = clientFactory(await store.credentials(run.company_id));
    for await (const page of client.batches("devices")) await store.writeDevices(run.id,page);
    for await (const page of client.batches("findings")) {
      const normalized = page.map(normalizeDefenderRecord);
      const records = normalized.filter((v): v is NonNullable<typeof v> => v !== null);
      await store.writeRecords(run.id,records,page.length,page.length-records.length);
      await new Promise<void>(resolve => setImmediate(resolve));
    }
    await store.finish(run);
  } catch (error) {
    await store.fail(run.id,error instanceof DefenderError ? error.message : "Import failed while processing or storing Defender data. Previous completed results are retained.");
  }
}
const runtime = globalThis as typeof globalThis & { __defenderWorker?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__defenderWorker ??= {};
export function triggerDefenderWorker(): Promise<void> {
  if (state.working) return state.working;
  state.working = (async () => {
    const { syncDefenderEnvironment } = await import("./defender-config");
    await syncDefenderEnvironment();
    const { reconcileDefenderPlatform } = await import("./defender-platform");
    // Also repairs already-completed imports and interrupted snapshot writes.
    await reconcileDefenderPlatform();
    const store = defenderStore();
    await store.schedule();
    const run = await store.claim();
    if (!run) return;
    const { ensureHydrated, getCompany } = await import("./store");
    await ensureHydrated();
    if (!getCompany(run.company_id)) { await store.fail(run.id,"The mapped customer no longer exists. Import stopped."); return; }
    await importDefenderRun(run,store);
    await reconcileDefenderPlatform();
    await store.prune(run.company_id).catch(() => {});
  })().catch(() => { console.error("[defender] Worker unavailable; queued imports will retry on the next worker tick."); })
    .finally(() => { state.working = undefined; });
  return state.working;
}
export function startDefenderWorker() {
  if (process.env.VULN_DISABLE_SCHEDULER === "true" || !process.env.DATABASE_URL || state.timer) return;
  state.timer = setInterval(() => { void triggerDefenderWorker(); },60_000);
  state.timer.unref();
  void triggerDefenderWorker();
}
