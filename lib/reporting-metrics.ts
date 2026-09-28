import type { Finding, Scan, Severity } from "./types";

export type ReportingFindingClass = "vuln" | "osint" | "pentest";

export function reportingFindingClass(connector: Finding["connector"]): ReportingFindingClass {
  if (connector === "spiderfoot" || connector === "artemis") return "osint";
  if (connector === "burp" || connector === "zap") return "pentest";
  return "vuln";
}

const openStatus = (status: Finding["status"]) => status === "Open" || status === "In Remediation";
const severityNames: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const cvePattern = /^CVE-\d{4}-\d{4,19}$/i;

export function buildReportingMetrics(companyId: string, findings: Finding[], scans: Scan[]) {
  const ownOpen = findings.filter(finding => finding.companyId === companyId && openStatus(finding.status));
  const remediation = ownOpen.filter(finding => reportingFindingClass(finding.connector) !== "osint");
  const osint = ownOpen.filter(finding => reportingFindingClass(finding.connector) === "osint");
  const web = ownOpen.filter(finding => reportingFindingClass(finding.connector) === "pentest");
  const ownScans = scans.filter(scan => scan.companyId === companyId);
  const assessed = remediation.length > 0 || ownScans.some(scan => scan.status === "Completed" &&
    reportingFindingClass(scan.connector) === "vuln");
  const bySeverity = Object.fromEntries(severityNames.map(name =>
    [name, remediation.filter(finding => finding.severity === name).length])) as Record<Severity, number>;
  return {
    vulnerabilities: {
      open: remediation.length,
      critical: bySeverity.Critical,
      high: bySeverity.High,
      kev: remediation.filter(finding => finding.kev).length,
      exploitable: remediation.filter(finding => finding.exploitAvailable).length,
      cveOpen: remediation.filter(finding => cvePattern.test(finding.cve)).length,
      bySeverity,
      assessed,
    },
    attackSurface: { open: osint.length },
    webTesting: { open: web.length, assessed: ownScans.some(scan => scan.status === "Completed" &&
      reportingFindingClass(scan.connector) === "pentest") },
  };
}

export type ReportingMetrics = ReturnType<typeof buildReportingMetrics>;
