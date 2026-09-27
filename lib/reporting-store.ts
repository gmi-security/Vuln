import { DashboardError } from "./elastic-dashboard";
import { computeExecReport, ensureHydrated, getCompany, listCompanies, listFindings } from "./store";

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
  const sources = new Map<string, number>();
  for (const finding of listFindings({ companyId: company.id })) {
    if (finding.status !== "Open" && finding.status !== "In Remediation") continue;
    for (const source of new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector]))
      sources.set(source, (sources.get(source) ?? 0) + 1);
  }
  return { report: { ...report, generatedAt: new Date().toISOString() },
    sources: [...sources].sort((a, b) => b[1] - a[1]).map(([name, open]) => ({ name, open })) };
}
