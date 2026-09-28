import type { Company, Finding, InventoryAsset, Scan } from "./types";
import { buildReportingMetrics, reportingFindingClass } from "./reporting-metrics";
import { buildSourceActivity } from "./reporting-source-activity";

type HistoryRow = { ts: string; data: unknown };
const isOpen = (finding: Finding) => finding.status === "Open" || finding.status === "In Remediation";

export function buildCustomerReportingModel(
  company: Pick<Company, "id" | "name">,
  findings: Finding[], scans: Scan[], assets: InventoryAsset[], history: HistoryRow[],
) {
  const ownFindings = findings.filter(finding => finding.companyId === company.id);
  const ownScans = scans.filter(scan => scan.companyId === company.id);
  const ownAssets = assets.filter(asset => asset.companyId === company.id);
  const metrics = buildReportingMetrics(company.id, ownFindings, ownScans);
  const sourceActivity = buildSourceActivity(company.id, ownScans, ownFindings, ownAssets);
  const actionable = ownFindings.filter(finding => isOpen(finding) && reportingFindingClass(finding.connector) !== "osint");
  const vulnerabilities = actionable.filter(finding => reportingFindingClass(finding.connector) === "vuln");
  const sorted = [...vulnerabilities].sort((a, b) => b.realRisk - a.realRisk || b.cvss - a.cvss);
  const findingRow = (finding: Finding) => ({ id: finding.id, cve: finding.cve, title: finding.title,
    asset: finding.asset, severity: finding.severity, realRisk: finding.realRisk, status: finding.status,
    lastSeen: finding.lastSeen, connectors: finding.seenBy?.length ? finding.seenBy : [finding.connector] });
  const orderedScans = [...ownScans].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const authoritativeFindingCount = actionable.filter(finding => finding.assetSource === "tidal" || finding.assetSource === "manual").length;
  return {
    company,
    metrics,
    assessmentState: metrics.vulnerabilities.assessed || actionable.length ? "assessed" as const : "unassessed" as const,
    sourceActivity,
    priorityTotal: vulnerabilities.length,
    priorityRows: sorted.slice(0, 25).map(findingRow),
    scanTotal: ownScans.length,
    recentScans: orderedScans.slice(0, 12).map(scan => ({ id: scan.id, name: scan.name,
      connector: scan.connector, status: scan.status, createdAt: scan.createdAt,
      completedAt: scan.completedAt, findingsCount: scan.findingsCount, hostsScanned: scan.hostsScanned })),
    assets: {
      inventoryCount: ownAssets.length,
      authoritativeFindingCount,
      contextCoveragePercent: actionable.length ? Math.round(authoritativeFindingCount / actionable.length * 100) : null,
      scanCoveragePercent: null as number | null,
      sourceCounts: [...new Set(ownAssets.map(asset => asset.source))].map(source => ({
        source, count: ownAssets.filter(asset => asset.source === source).length,
      })),
    },
    attackSurfaceRows: ownFindings.filter(finding => isOpen(finding) && reportingFindingClass(finding.connector) === "osint")
      .sort((a, b) => b.realRisk - a.realRisk).slice(0, 10).map(findingRow),
    webTestingRows: ownFindings.filter(finding => isOpen(finding) && reportingFindingClass(finding.connector) === "pentest")
      .sort((a, b) => b.realRisk - a.realRisk).slice(0, 10).map(findingRow),
    history: history.filter(row => row && typeof row.ts === "string" && typeof row.data === "object" && row.data !== null)
      .map(row => ({ ts: row.ts, open: typeof (row.data as { totalOpen?: unknown }).totalOpen === "number" ?
        (row.data as { totalOpen: number }).totalOpen : null })),
  };
}

export type CustomerReportingModel = ReturnType<typeof buildCustomerReportingModel>;
