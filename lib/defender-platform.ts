import { defenderStore } from "./defender-store";
import { ensureHydrated,defenderProjectedRun,publishDefenderSnapshot,flushNow } from "./store";

async function reconcile(refreshDependents: boolean) {
  await ensureHydrated();
  const store = defenderStore();
  let changed = false;
  for (const connection of await store.list()) {
    if (!connection.currentRun || defenderProjectedRun(connection.companyId) === connection.currentRun) continue;
    const snapshot = await store.platformSnapshot(connection.companyId);
    if (!snapshot) continue;
    publishDefenderSnapshot(snapshot);
    changed = true;
    await flushNow();
    console.info(`[defender] Published completed generation: ${snapshot.findings.length} device/CVE findings, ${snapshot.devices.length} devices.`);
  }
  if (changed && refreshDependents) {
    const { refreshDefenderRisk } = await import("./defender-risk");
    await refreshDefenderRisk(false);
    const { refreshReportingQueue } = await import("./reporting-queue");
    await refreshReportingQueue(true).catch(()=>{ console.error("[defender] Patch candidate refresh deferred to the reporting scheduler."); });
  }
}

const runtime = globalThis as typeof globalThis & { __defenderPublication?: Promise<void> };
export function reconcileDefenderPlatform(refreshDependents = true): Promise<void> {
  if (runtime.__defenderPublication) return runtime.__defenderPublication;
  runtime.__defenderPublication = reconcile(refreshDependents).finally(()=>{runtime.__defenderPublication=undefined;});
  return runtime.__defenderPublication;
}
