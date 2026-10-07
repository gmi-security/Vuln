import { defenderStore } from "./defender-store";
import { ensureHydrated,defenderProjectedRun,publishDefenderSnapshot,invalidateDefenderPublication,flushNow } from "./store";

async function reconcile(refreshDependents: boolean) {
  await ensureHydrated();
  const store = defenderStore();
  let changed = false;
  for (const connection of await store.list()) {
    if (!connection.currentRun || defenderProjectedRun(connection.companyId) === connection.currentRun) continue;
    const snapshot = await store.platformSnapshot(connection.companyId);
    if (!snapshot) continue;
    publishing.add(snapshot.companyId);
    try {
      publishDefenderSnapshot(snapshot);
      await flushNow({ throwOnError:true });
      changed = true;
    } catch (error) {
      invalidateDefenderPublication(snapshot.companyId,snapshot.runId);
      console.error("[defender] Shared findings were not saved; publication will retry from the completed import.");
      throw error;
    } finally {
      publishing.delete(snapshot.companyId);
    }
    console.info(`[defender] Published completed generation: ${snapshot.findings.length} device/CVE findings, ${snapshot.devices.length} devices.`);
  }
  if (changed && refreshDependents) {
    const { refreshDefenderRisk } = await import("./defender-risk");
    await refreshDefenderRisk(false);
    const { refreshReportingQueue } = await import("./reporting-queue");
    await refreshReportingQueue(true).catch(()=>{ console.error("[defender] Patch candidate refresh deferred to the reporting scheduler."); });
  }
}

const runtime = globalThis as typeof globalThis & { __defenderPublication?: Promise<void>; __defenderPublishing?: Set<string> };
const publishing = runtime.__defenderPublishing ??= new Set<string>();
export function defenderPublicationPending(companyId: string): boolean {
  return publishing.has(companyId);
}
export function reconcileDefenderPlatform(refreshDependents = true): Promise<void> {
  if (runtime.__defenderPublication) return runtime.__defenderPublication;
  runtime.__defenderPublication = reconcile(refreshDependents).finally(()=>{runtime.__defenderPublication=undefined;});
  return runtime.__defenderPublication;
}
