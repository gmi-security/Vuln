import type { Finding, Scan, Severity } from "./types";

const severityOrder: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export function buildCustomerInsights(companyId: string, findings: Finding[], allScans: Scan[]) {
  const scans = allScans.filter(scan => scan.companyId === companyId);
  const open = findings.filter(finding => finding.companyId === companyId && (finding.status === "Open" || finding.status === "In Remediation"));
  const severity = severityOrder.map(name => ({ name, count: open.filter(finding => finding.severity === name).length }));
  const sources = new Map<string, { name: string; scans: number; open: number }>();
  const source = (name: string) => {
    if (!sources.has(name)) sources.set(name, { name, scans: 0, open: 0 });
    return sources.get(name)!;
  };
  for (const scan of scans) source(scan.connector).scans++;
  for (const finding of open) {
    for (const connector of new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector])) source(connector).open++;
  }
  const sourceRows = [...sources.values()].sort((a, b) => b.open - a.open || b.scans - a.scans || a.name.localeCompare(b.name));
  const highestRisk = [...open].sort((a, b) => b.realRisk - a.realRisk || b.cvss - a.cvss).slice(0, 25)
    .map(finding => ({ id: finding.id, cve: finding.cve, title: finding.title, asset: finding.asset,
      severity: finding.severity, realRisk: finding.realRisk, connectors: [...new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector])] }));
  const recentScans = [...scans].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 12)
    .map(scan => ({ id: scan.id, name: scan.name, connector: scan.connector, status: scan.status,
      findingsCount: scan.findingsCount, completedAt: scan.completedAt, createdAt: scan.createdAt }));
  return { totalOpen: open.length, totalScans: scans.length, severity, sources: sourceRows, highestRisk, recentScans };
}

export type CustomerInsights = ReturnType<typeof buildCustomerInsights>;
