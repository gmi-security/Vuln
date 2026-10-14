import { createReportingSectionsAccumulator } from "./reporting-sections-accumulator";
import { createExecutiveReportAccumulator } from "./executive-report";
import { validateReportingCatalog, validateReportingSla } from "./reporting-policy";
import type { Company, Finding, InventoryAsset, Scan } from "./types";

// Both outputs are built from the same committed customer generation and time.
// No network requests, credentials, application store or background timers.
export function createReportingBundleAccumulator(company: Pick<Company, "id" | "name" | "industry">,
  context: { now: number; policy: { sla: unknown; catalog: unknown } }) {
  validateReportingSla(context.policy.sla);
  validateReportingCatalog(context.policy.catalog);
  if (typeof company.industry !== "string") throw new Error("Saved reporting customer industry required");
  const kev = new Set(context.policy.catalog.cves);
  const sections = createReportingSectionsAccumulator(company);
  const executive = createExecutiveReportAccumulator(company, { now: context.now, sla: context.policy.sla, isComplianceKev: cve => kev.has(cve) });
  return {
    finding(f: Finding) { sections.finding(f); executive.finding(f); },
    scan(s: Scan) { sections.scan(s); executive.scan(s); },
    asset(a: InventoryAsset) { sections.asset(a); executive.asset(a); },
    finish(history: { ts: string; data: unknown }[]) {
      return { ...sections.finish(history), executive: { ...executive.finish(),
        trend: history.map(row => ({ ts: row.ts, companyId: company.id, ...(row.data as Record<string, unknown>) })) },
        validUntil: context.now + 15 * 60_000 };
    },
  };
}
