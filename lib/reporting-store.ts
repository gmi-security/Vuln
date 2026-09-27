import { DashboardError } from "./elastic-dashboard";
import { buildCustomerInsights } from "./reporting-insights";
import { computeExecReport, ensureHydrated, getCompany, listCompanies, listFindings, listScans } from "./store";

export async function reportingSetup() {
  await ensureHydrated();
  return { companies: listCompanies().filter(company => company.kind === "client" && !company.isDemo)
    .map(company => ({ id: company.id, name: company.name })).sort((a, b) => a.name.localeCompare(b.name)) };
}

export async function reportingCustomer(appCompanyId: string) {
  if (typeof appCompanyId !== "string" || !appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose a customer.", 400);
  await ensureHydrated();
  const company = getCompany(appCompanyId);
  if (!company || company.kind !== "client" || company.isDemo) throw new DashboardError("Customer not found.", 404);
  const report = computeExecReport(company.id);
  if (!report) throw new DashboardError("Customer report is unavailable.", 404);
  const findings = listFindings({ companyId: company.id });
  const insights = buildCustomerInsights(company.id, findings, await listScans({ companyId: company.id }));
  return { report: { ...report, generatedAt: new Date().toISOString() },
    sources: insights.sources.map(({ name, open }) => ({ name, open })), insights };
}
