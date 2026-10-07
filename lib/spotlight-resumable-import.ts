import type { FalconTenant, SpotlightFinding } from "./crowdstrike";
import type { SpotlightCheckpoint, SpotlightPartitionCheckpoint, SpotlightPartitionedRunCheckpoint, SpotlightRecord } from "./spotlight-record-store";
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
  // CrowdStrike's own reported total result count for this run, known once
  // the first discovery page comes back (reportedTotal on savePage/
  // savePartitionPage). Null until then, or if CrowdStrike never reports
  // one -- callers must treat it as "no denominator yet", not zero.
  expectedCount: number | null;
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
    expectedCount: run?.expectedCount ?? null,
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

// Discovery walked as one sequential cursor is the bottleneck at real scale
// (a tenant with millions of findings can take hours just to enumerate IDs,
// one page at a time). This runs several independent cursor walks --
// partitioned by a field/value split already proven valid elsewhere in this
// codebase (see lib/crowdstrike.ts's SPOTLIGHT_DISCOVERY_PARTITIONS comment
// for why it's status:'open'/status:'reopen' and not a guessed facet) --
// concurrently. Hydration is untouched: it's already fanned out 8-wide and
// walks the whole run's deduped ID set regardless of which partition found
// each id, so it's shared as-is between both orchestrators.
export type SpotlightPartitionDef = { key: string; filter: string };

// Each reset re-walks the partition's filter from id 0 to get a fresh cursor
// -- wasteful but safe (already-discovered ids no-op on re-insert), so this
// is a backstop against a persistently broken filter/response, not a bound
// expected to bite in normal operation.
const MAX_PARTITION_CURSOR_RESETS = 20;

export type PartitionedSpotlightDependencies = {
  acquire: (tenantKey: string) => Promise<{ assertHeld: () => void; release: () => Promise<void> }>;
  createSession: (config: FalconTenant) => Promise<{
    queryPage: (after: string, filter: string) => Promise<{ ids: string[]; next: string; total: number | null }>;
    hydrateIds: (ids: string[]) => Promise<SpotlightFinding[]>;
  }>;
  begin: (tenantKey: string, partitionKeys: string[]) => Promise<SpotlightPartitionedRunCheckpoint>;
  getRunState: (runId: string, tenantKey: string) => Promise<SpotlightPartitionedRunCheckpoint>;
  savePartitionPage: (runId: string, tenantKey: string, partitionKey: string, priorCursor: string,
    ids: string[], nextCursor: string, reportedTotal: number | null) => Promise<SpotlightPartitionedRunCheckpoint>;
  resetPartition: (runId: string, tenantKey: string, partitionKey: string, reason: string) => Promise<void>;
  nextIds: (runId: string, tenantKey: string, afterId: string, limit?: number) => Promise<string[]>;
  write: (runId: string, tenantKey: string, ids: string[], rows: SpotlightRecord[]) => Promise<number>;
  complete: (runId: string, tenantKey: string) => Promise<{ findingsImported: number; hostsAffected: number }>;
  fail: (runId: string, error: string) => Promise<void>;
  prune: (tenantKey: string) => Promise<void>;
};

export async function runPartitionedSpotlightImport(
  selection: SpotlightTenantSelection,
  partitions: SpotlightPartitionDef[],
  deps: PartitionedSpotlightDependencies,
  onProgress: (progress: ResumableSpotlightProgress) => void,
): Promise<{ findingsImported: number; hostsAffected: number; skipped: number }> {
  let run: SpotlightPartitionedRunCheckpoint | undefined;
  let lock: Awaited<ReturnType<PartitionedSpotlightDependencies["acquire"]>> | undefined;
  const report = (phase: ResumableSpotlightProgress["phase"]) => onProgress({
    phase, tenant: selection.config.label,
    fetched: run?.discoveredCount ?? 0,
    stored: run?.hydratedCount ?? 0,
    expectedCount: run?.expectedCount ?? null,
  });
  report("Starting");
  try {
    lock = await deps.acquire(selection.tenantKey);
    lock.assertHeld();
    run = await deps.begin(selection.tenantKey, partitions.map(p => p.key));
    report(run.phase === "discovering" ? "Discovering" : "Hydrating");
    const session = await deps.createSession(selection.config);
    const filterByKey = new Map(partitions.map(p => [p.key, p.filter]));

    async function discoverPartition(state: SpotlightPartitionCheckpoint): Promise<void> {
      const filter = filterByKey.get(state.key);
      if (!filter) throw new Error(`No filter configured for Spotlight discovery partition "${state.key}".`);
      let cursor = state.queryCursor;
      let resets = 0;
      const seenCursors = new Set(cursor ? [cursor] : []);
      while (true) {
        lock!.assertHeld();
        const priorCursor = cursor;
        let page;
        try {
          page = await session.queryPage(priorCursor, filter);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          // CrowdStrike's "after" cursor backs a short-lived search context
          // (observed: a single retried, rate-limited page request can push
          // past its window and come back 404 "Search context expired"
          // instead of the 429 it was really hit for). A large tenant's walk
          // runs for hours and crosses CrowdStrike's rate limiter many times
          // over, so a single allowed reset isn't enough -- resetting only
          // restarts this partition's walk (already-discovered IDs are kept,
          // deduped by source_id on write), so repeated resets still make
          // real forward progress rather than looping forever on a truly
          // broken filter. Bounded anyway, so a persistently broken query
          // still fails loudly instead of burning hours silently.
          if (priorCursor && resets < MAX_PARTITION_CURSOR_RESETS && /^Spotlight query (400|404):/.test(message)) {
            await deps.resetPartition(run!.id, selection.tenantKey, state.key, `Saved Spotlight cursor rejected: ${message}`);
            cursor = ""; resets += 1; seenCursors.clear();
            continue;
          }
          throw error;
        }
        if (page.next && seenCursors.has(page.next)) throw new Error(`Spotlight pagination cursor repeated for partition "${state.key}".`);
        if (page.next) seenCursors.add(page.next);
        lock!.assertHeld();
        run = await deps.savePartitionPage(run!.id, selection.tenantKey, state.key, priorCursor, page.ids, page.next, page.total);
        report(run.phase === "discovering" ? "Discovering" : "Hydrating");
        cursor = page.next;
        if (!cursor) break;
        await new Promise<void>(resolve => setImmediate(resolve));
      }
    }

    if (run.phase === "discovering") {
      await Promise.all(run.partitions.filter(p => !p.done).map(discoverPartition));
      // The last write to `run` above is a race between whichever partition's
      // transaction happened to resolve last in JS -- not necessarily the one
      // Postgres actually committed last -- so re-read the true state rather
      // than trust it for the phase check below.
      run = await deps.getRunState(run.id, selection.tenantKey);
      report(run.phase === "discovering" ? "Discovering" : "Hydrating");
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
