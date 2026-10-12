import { applicationDatabase } from "./persist";
import { DashboardError } from "./elastic-dashboard";
import { readCustomerConnectorStatus } from "./customer-connector-status-service";
import { readCustomerReportingSections } from "./db/customer-reporting-sections.mjs";
import type { CustomerReportingModel } from "./reporting-customer-model";
import type { ExecReport } from "./executive-report";
import { readSavedApplicationCompanies } from "./db/connector-metadata.mjs";

export async function savedReportingSetup() {
  if (process.env.VULN_REPORTING_SQL_READS !== "true") return null;
  savedOverviewEnabled("setup-validation");
  const app = applicationDatabase();
  if (!app) throw new DashboardError("Saved reporting storage is unavailable.", 503);
  const client = await app.connect();
  try {
    const companies: { id: string; name: string; isDemo?: boolean }[] = await readSavedApplicationCompanies(client);
    if (new Set(companies.map(c => c.id)).size !== companies.length) throw new Error("Duplicate companies");
    return { companies: companies.filter(c => !c.isDemo).map(c => ({ id: c.id, name: c.name })).sort((a,b) => a.name.localeCompare(b.name)) };
  } catch { throw new DashboardError("Customer metadata is unavailable.", 503); }
  finally { client.release(); }
}

export function savedOverviewEnabled(companyId: string, env: Partial<NodeJS.ProcessEnv> = process.env) {
  if (env.VULN_REPORTING_SQL_READS !== "true") return false;
  const customers = (env.VULN_REPORTING_SQL_CUSTOMERS ?? "").split(",").map(v => v.trim());
  if (!customers.length || customers.length > 50 || new Set(customers).size !== customers.length ||
      customers.some(id => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(id)) || env.VULN_REPORTING_INPUT_REVISIONS !== "true")
    throw new DashboardError("Saved reporting configuration is incomplete.", 503);
  return customers.includes(companyId);
}

// No hydration, provider calls, scheduler tick, DDL, jobs or fallback aggregation.
// Turning the read flag off restores the existing Overview path immediately.
export async function savedReportingOverview(companyId: string) {
  const saved = await savedReportingResult(companyId);
  return saved ? { model: saved.model, savedReport: saved.savedReport } : null;
}

export async function savedReportingExecutive(companyId: string) {
  if (process.env.VULN_REPORTING_EXECUTIVE_ENABLED !== "true") return null;
  const saved = await savedReportingResult(companyId, true);
  if (!saved) return null;
  if (!saved.executive) throw new DashboardError("This customer's executive report is awaiting refresh.", 503);
  return { report: { ...saved.executive, generatedAt: saved.savedReport.capturedAt }, savedReport: saved.savedReport };
}

async function savedReportingResult(companyId: string, requireExecutive = false) {
  if (!savedOverviewEnabled(companyId)) return null;
  const app = applicationDatabase();
  if (!app) throw new DashboardError("Saved reporting storage is unavailable.", 503);
  try {
    const status = await readCustomerConnectorStatus(companyId);
    if (!("sourceSelection" in status) || status.sourceSelection?.state !== "reviewed")
      throw new DashboardError("Review this customer's connector assignments before using its saved report.", 503);
    const source = await app.connect();
    try {
      const target = await app.connect();
      try {
        const result = await readCustomerReportingSections(source, target, companyId,
          { mode: "published", expectedReviewRevision: status.sourceSelection.revision, requireExecutive });
        if (result.state !== "available" || !result.model)
          throw new DashboardError("This customer's saved report is awaiting refresh. Try again after the background refresh completes.", 503);
        return { model: result.model as CustomerReportingModel, executive: result.executive as (ExecReport & { trend?: unknown[] }) | undefined,
          savedReport: { capturedAt: result.capturedAt as string, builtAt: result.builtAt as string } };
      } finally { target.release(); }
    } finally { source.release(); }
  } catch (error) {
    if (error instanceof DashboardError) throw error;
    throw new DashboardError("This customer's saved report is unavailable. Check its source review and background refresh status.", 503);
  }
}
