import { executeEsql, type ElasticConnection } from "./elastic-query-client";
import { DashboardError, type QueryResult } from "./elastic-dashboard";

// AppSec (Trivy-scanned GitHub repos) reporting. A standalone, service-level
// Elastic connection -- not the per-user encrypted connection the Reporting
// page's custom tiles use, because this is a GMI-wide internal view, not
// scoped to one client. Same env-var config pattern as every other
// connector in this app (see lib/connectors.ts).
export function appsecElasticConfig(): ElasticConnection | null {
  const endpoint = process.env.APPSEC_ELASTIC_URL?.trim();
  const apiKey = process.env.APPSEC_ELASTIC_API_KEY?.trim();
  if (!endpoint || !apiKey) return null;
  return { endpoint, apiKey };
}

export const APPSEC_SCAN_STREAM = process.env.APPSEC_ELASTIC_SCAN_STREAM?.trim() || "gmi-appsec-scans";
export const APPSEC_FINDING_STREAM = process.env.APPSEC_ELASTIC_FINDING_STREAM?.trim() || "gmi-appsec-findings";

export type AppSecRepoRow = {
  repository: string;
  lastScan: string | null;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  secrets: number;
  newFindings: number;
  resolved: number;
  gate: string | null;
};

export type AppSecSummary = {
  repositories: number;
  gateFailures: number;
  critical: number;
  high: number;
  newCritical: number;
  newHigh: number;
  secrets: number;
  rows: AppSecRepoRow[];
};

function col(result: QueryResult, name: string): number {
  const i = result.columns.findIndex((c) => c.name === name);
  if (i < 0) throw new DashboardError(`AppSec query result is missing the "${name}" column.`);
  return i;
}

function asNumber(v: string | number | boolean | null): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function asString(v: string | number | boolean | null): string | null {
  return typeof v === "string" && v.length ? v : null;
}

// One row per repository, its most recent completed scan's state. LATEST()
// over a STATS ... BY repository keeps this cheap (one query, no per-repo
// round trips) and correct even as more of the other 49 repos start
// reporting in -- new repos just add rows, nothing else changes shape.
const SUMMARY_QUERY = `FROM ${APPSEC_SCAN_STREAM}
| WHERE \`gmi.appsec.scan.status\` == "completed"
| STATS
    last_scan = MAX(@timestamp),
    findings = LATEST(\`gmi.appsec.findings.total\`),
    critical = LATEST(\`gmi.appsec.severity.critical\`),
    high = LATEST(\`gmi.appsec.severity.high\`),
    medium = LATEST(\`gmi.appsec.severity.medium\`),
    low = LATEST(\`gmi.appsec.severity.low\`),
    secrets = LATEST(\`gmi.appsec.findings.secrets\`),
    new_findings = LATEST(\`gmi.appsec.findings.new\`),
    resolved = LATEST(\`gmi.appsec.findings.resolved\`),
    gate = LATEST(\`gmi.appsec.gate.result\`)
  BY repository = \`gmi.appsec.repository\`
| SORT critical DESC, high DESC, findings DESC
| LIMIT 100`;

export async function fetchAppSecSummary(): Promise<AppSecSummary> {
  const connection = appsecElasticConfig();
  if (!connection) throw new DashboardError("AppSec Elastic connection is not configured.");
  const result = await executeEsql(connection, SUMMARY_QUERY);
  const iRepo = col(result, "repository");
  const iLastScan = col(result, "last_scan");
  const iFindings = col(result, "findings");
  const iCritical = col(result, "critical");
  const iHigh = col(result, "high");
  const iMedium = col(result, "medium");
  const iLow = col(result, "low");
  const iSecrets = col(result, "secrets");
  const iNew = col(result, "new_findings");
  const iResolved = col(result, "resolved");
  const iGate = col(result, "gate");

  const rows: AppSecRepoRow[] = result.rows.map((r) => ({
    repository: asString(r[iRepo]) ?? "(unknown)",
    lastScan: asString(r[iLastScan]),
    findings: asNumber(r[iFindings]),
    critical: asNumber(r[iCritical]),
    high: asNumber(r[iHigh]),
    medium: asNumber(r[iMedium]),
    low: asNumber(r[iLow]),
    secrets: asNumber(r[iSecrets]),
    newFindings: asNumber(r[iNew]),
    resolved: asNumber(r[iResolved]),
    gate: asString(r[iGate]),
  }));

  let critical = 0, high = 0, newCritical = 0, newHigh = 0, secrets = 0, gateFailures = 0;
  for (const row of rows) {
    critical += row.critical;
    high += row.high;
    secrets += row.secrets;
    // Per-severity "new" isn't in the scan-level summary doc (only a total
    // new-findings count is) -- approximate "new critical/high" as the
    // overlap-free share of this repo's new findings that's critical/high
    // by the same proportion as its current mix, rather than guess at an
    // unconfirmed field name. Exact once the finding-level stream is wired
    // into the repo detail page, which has real per-finding first-seen data.
    if (row.findings > 0 && row.newFindings > 0) {
      newCritical += Math.round((row.critical / row.findings) * row.newFindings);
      newHigh += Math.round((row.high / row.findings) * row.newFindings);
    }
    if (row.gate && row.gate.toLowerCase() === "fail") gateFailures += 1;
  }

  return { repositories: rows.length, gateFailures, critical, high, newCritical, newHigh, secrets, rows };
}

export type AppSecFinding = {
  id: string;
  severity: string;
  cve: string | null;
  title: string;
  package: string | null;
  installedVersion: string | null;
  fixedVersion: string | null;
  status: string | null;
  firstSeen: string | null;
};

export type AppSecRepoDetail = {
  repository: string;
  scans: { scanId: string; completedAt: string | null; status: string | null; findings: number; critical: number; high: number; gate: string | null }[];
  findings: AppSecFinding[];
  findingsError: string | null;
};

const SCAN_HISTORY_QUERY = (repository: string) => `FROM ${APPSEC_SCAN_STREAM}
| WHERE \`gmi.appsec.repository\` == "${repository}" AND \`gmi.appsec.scan.status\` == "completed"
| KEEP @timestamp, \`gmi.appsec.scan.id\`, \`gmi.appsec.scan.status\`, \`gmi.appsec.findings.total\`, \`gmi.appsec.severity.critical\`, \`gmi.appsec.severity.high\`, \`gmi.appsec.gate.result\`
| SORT @timestamp DESC
| LIMIT 25`;

// Field names here follow the same gmi.appsec.* convention as the confirmed
// scan-level stream, but aren't verified against a real indexed finding doc
// yet -- kept isolated (own try/catch in the API route) so a wrong field
// name here degrades to "findings unavailable" instead of breaking the
// whole repo page, which still has real scan history either way.
const FINDINGS_QUERY = (repository: string) => `FROM ${APPSEC_FINDING_STREAM}
| WHERE \`gmi.appsec.repository\` == "${repository}" AND \`gmi.appsec.finding.status\` != "resolved"
| KEEP \`gmi.appsec.finding.id\`, \`gmi.appsec.finding.severity\`, \`gmi.appsec.finding.cve\`, \`gmi.appsec.finding.title\`, \`gmi.appsec.finding.package\`, \`gmi.appsec.finding.installed_version\`, \`gmi.appsec.finding.fixed_version\`, \`gmi.appsec.finding.status\`, \`gmi.appsec.finding.first_seen\`
| SORT \`gmi.appsec.finding.severity\` ASC
| LIMIT 100`;

// Escapes a repository name for safe interpolation into an ES|QL double-
// quoted string literal -- the only untrusted input these queries take
// (it comes from the URL path), so this is the one place injection matters.
function esqlStringLiteral(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export async function fetchAppSecRepoDetail(repository: string): Promise<AppSecRepoDetail> {
  const connection = appsecElasticConfig();
  if (!connection) throw new DashboardError("AppSec Elastic connection is not configured.");
  const safeName = esqlStringLiteral(repository);

  const scanResult = await executeEsql(connection, SCAN_HISTORY_QUERY(safeName));
  const iTs = col(scanResult, "@timestamp");
  const iScanId = col(scanResult, "gmi.appsec.scan.id");
  const iStatus = col(scanResult, "gmi.appsec.scan.status");
  const iFindings = col(scanResult, "gmi.appsec.findings.total");
  const iCritical = col(scanResult, "gmi.appsec.severity.critical");
  const iHigh = col(scanResult, "gmi.appsec.severity.high");
  const iGate = col(scanResult, "gmi.appsec.gate.result");
  const scans = scanResult.rows.map((r) => ({
    completedAt: asString(r[iTs]),
    scanId: asString(r[iScanId]) ?? "",
    status: asString(r[iStatus]),
    findings: asNumber(r[iFindings]),
    critical: asNumber(r[iCritical]),
    high: asNumber(r[iHigh]),
    gate: asString(r[iGate]),
  }));

  let findings: AppSecFinding[] = [];
  let findingsError: string | null = null;
  try {
    const findingResult = await executeEsql(connection, FINDINGS_QUERY(safeName));
    const iId = col(findingResult, "gmi.appsec.finding.id");
    const iSeverity = col(findingResult, "gmi.appsec.finding.severity");
    const iCve = col(findingResult, "gmi.appsec.finding.cve");
    const iTitle = col(findingResult, "gmi.appsec.finding.title");
    const iPackage = col(findingResult, "gmi.appsec.finding.package");
    const iInstalled = col(findingResult, "gmi.appsec.finding.installed_version");
    const iFixed = col(findingResult, "gmi.appsec.finding.fixed_version");
    const iFStatus = col(findingResult, "gmi.appsec.finding.status");
    const iFirstSeen = col(findingResult, "gmi.appsec.finding.first_seen");
    findings = findingResult.rows.map((r) => ({
      id: asString(r[iId]) ?? "",
      severity: asString(r[iSeverity]) ?? "Unknown",
      cve: asString(r[iCve]),
      title: asString(r[iTitle]) ?? asString(r[iCve]) ?? "Untitled finding",
      package: asString(r[iPackage]),
      installedVersion: asString(r[iInstalled]),
      fixedVersion: asString(r[iFixed]),
      status: asString(r[iFStatus]),
      firstSeen: asString(r[iFirstSeen]),
    }));
  } catch (err) {
    findingsError = err instanceof Error ? err.message : "Could not load findings.";
  }

  return { repository, scans, findings, findingsError };
}
