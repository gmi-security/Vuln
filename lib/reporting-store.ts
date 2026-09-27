import { DashboardError } from "./elastic-dashboard";
import { cwOptions } from "./connectwise-client";
import { patchTicketDatabase, savedConnection } from "./patch-ticket-store";
import { computeExecReport, ensureHydrated, getCompany, listCompanies, listFindings } from "./store";
import { exactCompanyMatch } from "./reporting-company-match";

const reportingDatabase = patchTicketDatabase;

export async function reportingSetup() {
  await ensureHydrated();
  const companies = listCompanies().filter(company => company.kind === "client" && !company.isDemo)
    .map(company => ({ id: company.id, name: company.name }));
  try {
    const saved = await savedConnection();
    return { configured: true, revision: saved.revision, companies };
  } catch (error) {
    if (error instanceof DashboardError && error.status === 409) return { configured: false, companies };
    throw error;
  }
}

function validCWId(value: number) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new DashboardError("Choose a ConnectWise company.", 400);
}

export async function reportingCustomer(cwCompanyId: number) {
  validCWId(cwCompanyId);
  const saved = await savedConnection();
  const db = await reportingDatabase();
  const row = (await db.query("SELECT app_company_id, cw_company_name FROM reporting_company_links WHERE cw_target=$1 AND cw_company_id=$2", [saved.target, cwCompanyId])).rows[0];
  if (!row) return { linked: false };
  await ensureHydrated();
  const company = getCompany(row.app_company_id);
  if (!company || company.kind !== "client" || company.isDemo) return { linked: false };
  const report = computeExecReport(company.id);
  if (!report) return { linked: false };
  const sources = new Map<string, number>();
  for (const finding of listFindings({ companyId: company.id })) {
    if (finding.status !== "Open" && finding.status !== "In Remediation") continue;
    for (const source of new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector]))
      sources.set(source, (sources.get(source) ?? 0) + 1);
  }
  return { linked: true, appCompanyId: company.id, cwCompanyName: row.cw_company_name,
    report: { ...report, generatedAt: new Date().toISOString() },
    sources: [...sources].sort((a, b) => b[1] - a[1]).map(([name, open]) => ({ name, open })) };
}

export async function reportingLinkForAppCompany(appCompanyId: string) {
  if (!appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose an app customer.", 400);
  const saved = await savedConnection();
  const db = await reportingDatabase();
  const row = (await db.query("SELECT cw_company_id FROM reporting_company_links WHERE cw_target=$1 AND app_company_id=$2", [saved.target, appCompanyId])).rows[0];
  return { cwCompanyId: row?.cw_company_id ?? null };
}

export async function autoLinkReportingCompany(cwCompanyId: number, actor: string) {
  validCWId(cwCompanyId);
  const existing = await reportingCustomer(cwCompanyId);
  if (existing.linked) return existing;
  const saved = await savedConnection();
  const selected = (await cwOptions(saved.value, "companies", undefined, 1, "", cwCompanyId)).options.find(option => option.id === cwCompanyId);
  if (!selected) throw new DashboardError("ConnectWise company is unavailable.", 400);
  await ensureHydrated();
  const company = exactCompanyMatch(selected.name, listCompanies().filter(item => item.kind === "client" && !item.isDemo));
  if (!company) return { linked: false, matchReason: "No unique exact customer name match was found. Choose the matching app customer once." };
  const db = await reportingDatabase();
  try {
    await db.query(`INSERT INTO reporting_company_links (cw_target,cw_company_id,app_company_id,cw_company_name,linked_by)
      VALUES ($1,$2,$3,$4,$5) ON CONFLICT (cw_target,cw_company_id) DO NOTHING`,
      [saved.target, cwCompanyId, company.id, selected.name, actor]);
  } catch (error) {
    if ((error as { code?: string }).code === "23505") return { linked: false, matchReason: "This customer is linked to another ConnectWise company. Choose the correct customer manually." };
    throw error;
  }
  await db.query("DELETE FROM reporting_queue_runs WHERE id=1");
  return reportingCustomer(cwCompanyId);
}

export async function linkReportingCompany(cwCompanyId: number, appCompanyId: string, actor: string) {
  validCWId(cwCompanyId);
  if (typeof appCompanyId !== "string" || !appCompanyId || appCompanyId.length > 100) throw new DashboardError("Choose an app customer.", 400);
  await ensureHydrated();
  const company = getCompany(appCompanyId);
  if (!company || company.kind !== "client" || company.isDemo) throw new DashboardError("Choose a valid customer.", 400);
  const saved = await savedConnection();
  const selected = (await cwOptions(saved.value, "companies", undefined, 1, "", cwCompanyId)).options.find(option => option.id === cwCompanyId);
  if (!selected) throw new DashboardError("ConnectWise company is unavailable.", 400);
  const db = await reportingDatabase();
  try {
    await db.query(`INSERT INTO reporting_company_links (cw_target,cw_company_id,app_company_id,cw_company_name,linked_by)
      VALUES ($1,$2,$3,$4,$5) ON CONFLICT (cw_target,cw_company_id) DO UPDATE SET
      app_company_id=EXCLUDED.app_company_id,cw_company_name=EXCLUDED.cw_company_name,
      linked_by=EXCLUDED.linked_by,linked_at=now()`, [saved.target, cwCompanyId, appCompanyId, selected.name, actor]);
  } catch (error) {
    if ((error as { code?: string }).code === "23505") throw new DashboardError("That app customer is already linked to another ConnectWise company.", 409);
    throw error;
  }
  await db.query("DELETE FROM reporting_queue_runs WHERE id=1");
  return { linked: true };
}
