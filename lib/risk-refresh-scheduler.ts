import { elasticVulnEnabled } from "./elastic-vuln-server";
import { refreshCveEnrichment } from "./cve-enrichment-refresh";
import { computeFindingRiskForTenant } from "./finding-risk-compute";
import { riskScoringDatabase, recordRiskSnapshot } from "./risk-scoring-store";
import { reconcileTicketPriorityToSwath } from "./swath-ticket-priority";
import { recordJobRun } from "./background-job-runs";

const RISK_REFRESH_JOB = "risk-refresh";

// One pass: for every tenant with a current (completed) Spotlight generation,
// refresh CISA KEV/EPSS for that tenant's actual CVEs (not the whole
// universe -- see cve-enrichment-refresh.ts), then recompute finding_risk.
// KEV/EPSS/scoring never run during page rendering (the RBVM spec's "no
// unnecessary external requests during normal page rendering" requirement)
// -- this scheduler is the only thing that calls out to CISA/FIRST.org.
async function refreshTenant(tenantKey: string, companyId: string): Promise<{ scored: number; errors: number }> {
  const db = await riskScoringDatabase();
  const cves = (await db.query(
    "SELECT DISTINCT cve FROM spotlight_import_records r JOIN spotlight_import_current c ON c.tenant_key=r.tenant_key AND c.run_id=r.run_id WHERE r.tenant_key=$1",
    [tenantKey],
  )).rows.map((row: { cve: string }) => row.cve);
  const enrichResult = await refreshCveEnrichment(cves);
  const computeResult = await computeFindingRiskForTenant(tenantKey, companyId);
  return { scored: computeResult.findingsScored, errors: enrichResult.errors + computeResult.errors };
}

export type RiskRefreshResult = { tenantsProcessed: number; findingsScored: number; errors: number };

export async function refreshAllTenantsRisk(): Promise<RiskRefreshResult> {
  const db = await riskScoringDatabase();
  const tenants = (await db.query("SELECT DISTINCT r.tenant_key, r.company_id FROM spotlight_import_records r JOIN spotlight_import_current c ON c.tenant_key=r.tenant_key AND c.run_id=r.run_id"))
    .rows as { tenant_key: string; company_id: string }[];
  let findingsScored = 0, errors = 0;
  for (const { tenant_key, company_id } of tenants) {
    try {
      const result = await refreshTenant(tenant_key, company_id);
      findingsScored += result.scored; errors += result.errors;
      await recordRiskSnapshot(db, company_id);
    } catch {
      errors++; // one tenant's failure (CrowdStrike timeout, malformed data) must not block the rest
    }
  }
  if (tenants.length) await recordRiskSnapshot(db, "global").catch(() => {});
  // Ticket priority reconciliation reads finding_risk, so it runs after
  // scoring completes for this pass, not interleaved per-tenant.
  await reconcileTicketPriorityToSwath().catch((err) => { errors++; console.error("[risk-refresh] priority reconciliation failed:", err instanceof Error ? err.message : err); });
  return { tenantsProcessed: tenants.length, findingsScored, errors };
}

const RISK_REFRESH_LOCK_KEY = 804212; // next free advisory-lock key after close-and-recut's 804211 (see lib/group-ticket-reconciliation.ts)
const runtime = globalThis as typeof globalThis & { __riskRefresh?: { timer?: ReturnType<typeof setInterval>; working?: Promise<void> } };
const state = runtime.__riskRefresh ??= {};

// 30 minutes: KEV/EPSS don't change minute-to-minute, and a full tenant
// rescore is meaningfully heavier than the 5/15-minute ticket-status loops.
function runOnce(): Promise<void> {
  if (state.working) return state.working;
  state.working = (async () => {
    const db = await riskScoringDatabase();
    const lock = await db.query("SELECT pg_try_advisory_lock($1) AS locked", [RISK_REFRESH_LOCK_KEY]);
    if (!lock.rows[0].locked) return;
    try {
      // Job-run bookkeeping is diagnostic, not load-bearing -- a failure
      // writing to background_job_runs (e.g. a permissions gap on that one
      // table) must never abort the actual refresh, and must never happen
      // before the lock is held by the try/finally that releases it. This
      // was a real bug: recordJobRun("running") used to run BEFORE this
      // try block, so when it threw, pg_advisory_unlock never ran and the
      // lock stayed held forever -- every future scheduled pass silently
      // no-op'd until the process restarted.
      await recordJobRun(RISK_REFRESH_JOB, "running").catch((err) => console.error("[risk-refresh] could not record job start:", err instanceof Error ? err.message : err));
      const result = await refreshAllTenantsRisk();
      await recordJobRun(RISK_REFRESH_JOB, "succeeded", result).catch((err) => console.error("[risk-refresh] could not record job success:", err instanceof Error ? err.message : err));
    } catch (err) {
      await recordJobRun(RISK_REFRESH_JOB, "failed", undefined, err instanceof Error ? err.message : String(err)).catch(() => {});
      throw err;
    } finally {
      await db.query("SELECT pg_advisory_unlock($1)", [RISK_REFRESH_LOCK_KEY]).catch(() => {});
    }
  })().then(() => {}, (err) => console.error("[risk-refresh] Could not complete:", err instanceof Error ? err.message : err))
    .finally(() => { state.working = undefined; });
  return state.working;
}

export function startRiskRefreshScheduler(): void {
  if (state.timer || !elasticVulnEnabled() || process.env.VULN_DISABLE_SCHEDULER === "true") return;
  state.timer = setInterval(runOnce, 30 * 60_000);
  state.timer.unref();
  runOnce();
}

// Fire-and-forget, same pattern as validate-closures/close-and-recut: a full
// pass calls out to CISA/FIRST.org and walks every tenant's Spotlight
// generation, comfortably past this app's 20-second request timeout. Check
// progress via GET .../job-status?job=risk-refresh.
export function triggerRiskRefreshNow(): { started: boolean } {
  if (state.working) return { started: false };
  void runOnce();
  return { started: true };
}
