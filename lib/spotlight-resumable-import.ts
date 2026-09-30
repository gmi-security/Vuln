import type { FalconTenant, SpotlightFinding } from "./crowdstrike";
import type { SpotlightCheckpoint, SpotlightRecord } from "./spotlight-record-store";
import type { SpotlightTenantSelection } from "./spotlight-import";

export type ResumableSpotlightDependencies = {
  acquire: (tenantKey: string) => Promise<{ assertHeld: () => void; release: () => Promise<void> }>;
  createSession: (config: FalconTenant) => Promise<{
    queryPage: (after: string) => Promise<{ ids: string[]; next: string; total: number | null }>;
    hydrateIds: (ids: string[]) => Promise<SpotlightFinding[]>;
  }>;
  begin: (tenantKey: string) => Promise<SpotlightCheckpoint>;
  savePage: (runId: string, tenantKey: string, priorCursor: string, ids: string[],
    nextCursor: string, reportedTotal: number | null) => Promise<SpotlightCheckpoint>;
  nextIds: (runId: string, tenantKey: string, afterId: string, limit?: number) => Promise<string[]>;
  write: (runId: string, tenantKey: string, ids: string[], rows: SpotlightRecord[]) => Promise<number>;
  complete: (runId: string, tenantKey: string) => Promise<{ findingsImported: number; hostsAffected: number }>;
  fail: (runId: string, error: string) => Promise<void>;
  abandon: (runId: string, tenantKey: string, reason: string) => Promise<void>;
  prune: (tenantKey: string) => Promise<void>;
};

export type ResumableSpotlightProgress = {
  phase: "Starting" | "Discovering" | "Hydrating" | "Completing";
  tenant: string;
  fetched: number;
  stored: number;
};

export async function runResumableSpotlightImport(
  selection: SpotlightTenantSelection,
  deps: ResumableSpotlightDependencies,
  onProgress: (progress: ResumableSpotlightProgress) => void,
): Promise<{ findingsImported: number; hostsAffected: number; skipped: number }> {
  let run: SpotlightCheckpoint | undefined;
  let lock: Awaited<ReturnType<ResumableSpotlightDependencies["acquire"]>> | undefined;
  const report = (phase: ResumableSpotlightProgress["phase"]) => onProgress({
    phase, tenant: selection.config.label,
    fetched: run?.discoveredCount ?? 0,
    stored: run?.hydratedCount ?? 0,
  });
  report("Starting");
  try {
    lock = await deps.acquire(selection.tenantKey);
    lock.assertHeld();
    run = await deps.begin(selection.tenantKey);
    report(run.phase === "discovering" ? "Discovering" : "Hydrating");
    const session = await deps.createSession(selection.config);
    let resetInvalidCursor = false;
    const seenCursors = new Set(run.queryCursor ? [run.queryCursor] : []);
    while (run.phase === "discovering") {
      lock.assertHeld();
      const priorCursor = run.queryCursor;
      let page;
      try {
        page = await session.queryPage(priorCursor);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (priorCursor && !resetInvalidCursor && /^Spotlight query (400|404):/.test(message)) {
          await deps.abandon(run.id, selection.tenantKey, `Saved Spotlight cursor rejected: ${message}`);
          run = await deps.begin(selection.tenantKey);
          resetInvalidCursor = true;
          seenCursors.clear();
          report("Discovering");
          continue;
        }
        throw error;
      }
      if (page.next && seenCursors.has(page.next)) throw new Error("Spotlight pagination cursor repeated.");
      if (page.next) seenCursors.add(page.next);
      lock.assertHeld();
      run = await deps.savePage(run.id, selection.tenantKey, priorCursor,
        page.ids, page.next, page.total);
      report(run.phase === "discovering" ? "Discovering" : "Hydrating");
      await new Promise<void>(resolve => setImmediate(resolve));
    }
    while (run.phase === "hydrating") {
      lock.assertHeld();
      const ids = await deps.nextIds(run.id, selection.tenantKey, run.hydrationCursor, 3200);
      if (!ids.length) break;
      const findings = await session.hydrateIds(ids);
      const expected = new Set(ids);
      if (findings.length !== ids.length ||
          new Set(findings.map(item => item.id)).size !== ids.length ||
          findings.some(item => !expected.has(item.id) || item.raw == null))
        throw new Error("Spotlight entity hydration IDs mismatch with staged discovery IDs.");
      const observedAt = new Date().toISOString();
      const rows: SpotlightRecord[] = findings.map(item => ({
        sourceId: item.id, tenantKey: selection.tenantKey, companyId: selection.companyId,
        hostname: item.hostname, localIp: item.localIp, externalIp: item.externalIp,
        cve: item.cve, severity: item.severity, status: item.status,
        description: item.description, remediation: item.remediation,
        observedAt, raw: item.raw,
      }));
      lock.assertHeld();
      const stored = await deps.write(run.id, selection.tenantKey, ids, rows);
      if (stored !== ids.length) throw new Error("Spotlight hydration write count mismatch.");
      run = { ...run, hydrationCursor: ids[ids.length - 1], hydratedCount: run.hydratedCount + stored };
      report("Hydrating");
      await new Promise<void>(resolve => setImmediate(resolve));
    }
    report("Completing");
    lock.assertHeld();
    const result = await deps.complete(run.id, selection.tenantKey);
    void deps.prune(selection.tenantKey).catch(error => {
      console.error("[spotlight] old generation cleanup failed:", error);
    });
    return { ...result, skipped: 0 };
  } catch (error) {
    let ownsRun = false;
    try { lock?.assertHeld(); ownsRun = Boolean(lock); } catch { /* Another worker may own it now. */ }
    if (run && ownsRun)
      await deps.fail(run.id, error instanceof Error ? error.message : String(error)).catch(() => {});
    throw error;
  } finally {
    await lock?.release();
  }
}
