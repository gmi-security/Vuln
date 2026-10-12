import { savedReportingOverview, savedReportingSetup } from "./reporting-saved-overview";
import { DashboardError } from "./elastic-dashboard";
import { buildCustomerInsights } from "./reporting-insights";
import { buildCustomerReportingModel } from "./reporting-customer-model";
import { loadMetricsHistory, loadLegacyCustomerMetricsHistory } from "./persist";
import { computeExecReport, ensureHydrated, listAssets, listCompanies, listFindings, listScans } from "./store";
import { resolveCustomerScope } from "./customer-scope";

// Includes GMI's own internal estate (kind "internal") alongside client
// companies — GMI scans and tickets its own infrastructure through this same
// pipeline, and needs the same explicit-selection scoping everyone else gets
// rather than being permanently unreachable from the customer picker. Demo
// companies (e.g. SplashWorks) are still excluded everywhere.
export async function reportingSetup() {
  const saved = await savedReportingSetup();
  if (saved) return saved;
  await ensureHydrated();
  return { companies: listCompanies().filter(company => !company.isDemo)
    .map(company => ({ id: company.id, name: company.name })).sort((a, b) => a.name.localeCompare(b.name)) };
}

export async function reportingCustomer(appCompanyId: string) {
  if (typeof appCompanyId !== "string" || !appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose a customer.", 400);
  const { company } = await resolveCustomerScope(appCompanyId);
  const report = computeExecReport(company.id);
  if (!report) throw new DashboardError("Customer report is unavailable.", 404);
  const findings = listFindings({ companyId: company.id });
  const scans = await listScans({ companyId: company.id });
  const insights = buildCustomerInsights(company.id, findings, scans);
  const [history, legacyHistory] = await Promise.all([loadMetricsHistory(company.id, 180), loadLegacyCustomerMetricsHistory(company.id)]);
  const model = buildCustomerReportingModel(company, findings, scans, listAssets({ companyId: company.id }), history, legacyHistory);
  return { report: { ...report, generatedAt: new Date().toISOString() },
    sources: insights.sources.map(({ name, open }) => ({ name, open })), insights, model };
}

// Overview renders only these sections. Avoid computing unused executive
// risk/compliance/SLA and a second insights aggregation on that request.
// The SQL path is opt-in per customer; other customers retain existing reads.
export async function reportingOverview(appCompanyId: string) {
  if (typeof appCompanyId !== "string" || !appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose a customer.", 400);
  const saved = await savedReportingOverview(appCompanyId);
  if (saved) return saved;
  const { company } = await resolveCustomerScope(appCompanyId);
  const findings = listFindings({ companyId: company.id });
  const scans = await listScans({ companyId: company.id });
  const [history, legacyHistory] = await Promise.all([loadMetricsHistory(company.id, 180), loadLegacyCustomerMetricsHistory(company.id)]);
  const model = buildCustomerReportingModel(company, findings, scans, listAssets({ companyId: company.id }), history, legacyHistory);
  return { model };
}
