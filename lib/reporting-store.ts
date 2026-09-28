import { DashboardError } from "./elastic-dashboard";
import { buildCustomerInsights } from "./reporting-insights";
import { buildCustomerReportingModel } from "./reporting-customer-model";
import { loadMetricsHistory } from "./persist";
import { computeExecReport, ensureHydrated, getCompany, listAssets, listCompanies, listFindings, listScans } from "./store";

// Includes GMI's own internal estate (kind "internal") alongside client
// companies — GMI scans and tickets its own infrastructure through this same
// pipeline, and needs the same explicit-selection scoping everyone else gets
// rather than being permanently unreachable from the customer picker. Demo
// companies (e.g. SplashWorks) are still excluded everywhere.
export async function reportingSetup() {
  await ensureHydrated();
  return { companies: listCompanies().filter(company => !company.isDemo)
    .map(company => ({ id: company.id, name: company.name })).sort((a, b) => a.name.localeCompare(b.name)) };
}

export async function reportingCustomer(appCompanyId: string) {
  if (typeof appCompanyId !== "string" || !appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose a customer.", 400);
  await ensureHydrated();
  const company = getCompany(appCompanyId);
  if (!company || company.isDemo) throw new DashboardError("Customer not found.", 404);
  const report = computeExecReport(company.id);
  if (!report) throw new DashboardError("Customer report is unavailable.", 404);
  const findings = listFindings({ companyId: company.id });
  const scans = await listScans({ companyId: company.id });
  const insights = buildCustomerInsights(company.id, findings, scans);
  const model = buildCustomerReportingModel(company, findings, scans, listAssets({ companyId: company.id }), await loadMetricsHistory(company.id, 180));
  return { report: { ...report, generatedAt: new Date().toISOString() },
    sources: insights.sources.map(({ name, open }) => ({ name, open })), insights, model };
}
