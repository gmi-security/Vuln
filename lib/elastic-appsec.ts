import { executeEsql, type ElasticConnection } from "./elastic-query-client";
import { DashboardError, type QueryResult } from "./elastic-dashboard";

export function appsecElasticConfig(): ElasticConnection | null {
  const endpoint = process.env.APPSEC_ELASTIC_URL?.trim();
  const apiKey = process.env.APPSEC_ELASTIC_API_KEY?.trim();
  if (!endpoint || !apiKey) return null;
  return { endpoint, apiKey };
}

export const APPSEC_SCAN_STREAM = process.env.APPSEC_ELASTIC_SCAN_STREAM?.trim() || "gmi-appsec-scans";
export const APPSEC_FINDING_STREAM = process.env.APPSEC_ELASTIC_FINDING_STREAM?.trim() || "gmi-appsec-findings";

const TARGET_REPOSITORIES = Math.max(1, Number.parseInt(process.env.GMI_APPSEC_REPOSITORY_TOTAL || "50", 10) || 50);

export type AppSecRepoRow = {
  repository: string;
  lastScan: string | null;
  findings: number;
  vulnerabilities: number;
  misconfigurations: number;
  licenses: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  secrets: number;
  newFindings: number;
  newCritical: number;
  newHigh: number;
  resolved: number;
  gate: string | null;
};

export type AppSecSummary = {
  repositories: number;
  totalRepositories: number;
  coveragePct: number;
  findings: number;
  vulnerabilities: number;
  misconfigurations: number;
  licenses: number;
  gateFailures: number;
  critical: number;
  high: number;
  newCritical: number;
  newHigh: number;
  secrets: number;
  resolved: number;
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

const SUMMARY_QUERY = `FROM ${APPSEC_SCAN_STREAM}
| WHERE \`gmi.appsec.scan.status\` == "completed"
| STATS
    last_scan = MAX(@timestamp),
    findings = LATEST(\`gmi.appsec.findings.total\`),
    vulnerabilities = LATEST(\`gmi.appsec.findings.vulnerabilities\`),
    misconfigurations = LATEST(\`gmi.appsec.findings.misconfigurations\`),
    licenses = LATEST(\`gmi.appsec.findings.licenses\`),
    critical = LATEST(\`gmi.appsec.severity.critical\`),
    high = LATEST(\`gmi.appsec.severity.high\`),
    medium = LATEST(\`gmi.appsec.severity.medium\`),
    low = LATEST(\`gmi.appsec.severity.low\`),
    secrets = LATEST(\`gmi.appsec.findings.secrets\`),
    new_findings = LATEST(\`gmi.appsec.delta.new.total\`),
    new_critical = LATEST(\`gmi.appsec.delta.new.critical\`),
    new_high = LATEST(\`gmi.appsec.delta.new.high\`),
    resolved = LATEST(\`gmi.appsec.delta.resolved.total\`),
    gate = LATEST(\`gmi.appsec.gate.result\`)
  BY repository = \`gmi.appsec.repository\`
| SORT critical DESC, high DESC, findings DESC
| LIMIT 100`;

export async function fetchAppSecSummary(): Promise<AppSecSummary> {
  const connection = appsecElasticConfig();
  if (!connection) throw new DashboardError("AppSec Elastic connection is not configured.");

  const result = await executeEsql(connection, SUMMARY_QUERY);
  const idx = Object.fromEntries([
    "repository", "last_scan", "findings", "vulnerabilities", "misconfigurations", "licenses",
    "critical", "high", "medium", "low", "secrets", "new_findings", "new_critical", "new_high", "resolved", "gate",
  ].map((name) => [name, col(result, name)])) as Record<string, number>;

  const rows: AppSecRepoRow[] = result.rows.map((r) => ({
    repository: asString(r[idx.repository]) ?? "(unknown)",
    lastScan: asString(r[idx.last_scan]),
    findings: asNumber(r[idx.findings]),
    vulnerabilities: asNumber(r[idx.vulnerabilities]),
    misconfigurations: asNumber(r[idx.misconfigurations]),
    licenses: asNumber(r[idx.licenses]),
    critical: asNumber(r[idx.critical]),
    high: asNumber(r[idx.high]),
    medium: asNumber(r[idx.medium]),
    low: asNumber(r[idx.low]),
    secrets: asNumber(r[idx.secrets]),
    newFindings: asNumber(r[idx.new_findings]),
    newCritical: asNumber(r[idx.new_critical]),
    newHigh: asNumber(r[idx.new_high]),
    resolved: asNumber(r[idx.resolved]),
    gate: asString(r[idx.gate]),
  }));

  const totals = rows.reduce((acc, row) => {
    acc.findings += row.findings;
    acc.vulnerabilities += row.vulnerabilities;
    acc.misconfigurations += row.misconfigurations;
    acc.licenses += row.licenses;
    acc.critical += row.critical;
    acc.high += row.high;
    acc.newCritical += row.newCritical;
    acc.newHigh += row.newHigh;
    acc.secrets += row.secrets;
    acc.resolved += row.resolved;
    if (row.gate?.toLowerCase() === "fail") acc.gateFailures += 1;
    return acc;
  }, { findings: 0, vulnerabilities: 0, misconfigurations: 0, licenses: 0, critical: 0, high: 0, newCritical: 0, newHigh: 0, secrets: 0, resolved: 0, gateFailures: 0 });

  return {
    repositories: rows.length,
    totalRepositories: TARGET_REPOSITORIES,
    coveragePct: Math.round((rows.length * 1000) / TARGET_REPOSITORIES) / 10,
    ...totals,
    rows,
  };
}

export type AppSecFinding = {
  fingerprint: string;
  id: string;
  severity: string;
  kind: string;
  vulnerabilityId: string | null;
  title: string;
  package: string | null;
  target: string | null;
  status: string | null;
  observedAt: string | null;
};

export type AppSecScanHistory = {
  scanId: string;
  completedAt: string | null;
  status: string | null;
  findings: number;
  critical: number;
  high: number;
  newCritical: number;
  newHigh: number;
  resolved: number;
  gate: string | null;
};

export type AppSecRepoDetail = {
  repository: string;
  scans: AppSecScanHistory[];
  findings: AppSecFinding[];
  findingsError: string | null;
};

function esqlStringLiteral(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

const SCAN_HISTORY_QUERY = (repository: string) => `FROM ${APPSEC_SCAN_STREAM}
| WHERE \`gmi.appsec.repository\` == "${repository}" AND \`gmi.appsec.scan.status\` == "completed"
| KEEP @timestamp, \`gmi.appsec.scan.id\`, \`gmi.appsec.scan.status\`, \`gmi.appsec.findings.total\`, \`gmi.appsec.severity.critical\`, \`gmi.appsec.severity.high\`, \`gmi.appsec.delta.new.critical\`, \`gmi.appsec.delta.new.high\`, \`gmi.appsec.delta.resolved.total\`, \`gmi.appsec.gate.result\`
| SORT @timestamp DESC
| LIMIT 25`;

const FINDINGS_QUERY = (repository: string, scanId: string) => `FROM ${APPSEC_FINDING_STREAM}
| WHERE \`gmi.appsec.repository\` == "${repository}"
  AND \`gmi.appsec.scan.id\` == "${scanId}"
  AND \`gmi.appsec.finding.status\` != "resolved"
| KEEP @timestamp, \`gmi.appsec.finding.fingerprint\`, \`gmi.appsec.finding.id\`, \`gmi.appsec.finding.severity\`, \`gmi.appsec.finding.kind\`, \`gmi.appsec.finding.title\`, \`gmi.appsec.finding.target\`, \`gmi.appsec.finding.status\`, \`package.name\`, \`vulnerability.id\`
| SORT \`gmi.appsec.finding.severity\` ASC
| LIMIT 100`;

export async function fetchAppSecRepoDetail(repository: string): Promise<AppSecRepoDetail> {
  const connection = appsecElasticConfig();
  if (!connection) throw new DashboardError("AppSec Elastic connection is not configured.");
  const safeName = esqlStringLiteral(repository);

  const scanResult = await executeEsql(connection, SCAN_HISTORY_QUERY(safeName));
  const idx = Object.fromEntries([
    "@timestamp", "gmi.appsec.scan.id", "gmi.appsec.scan.status", "gmi.appsec.findings.total",
    "gmi.appsec.severity.critical", "gmi.appsec.severity.high", "gmi.appsec.delta.new.critical",
    "gmi.appsec.delta.new.high", "gmi.appsec.delta.resolved.total", "gmi.appsec.gate.result",
  ].map((name) => [name, col(scanResult, name)])) as Record<string, number>;

  const scans: AppSecScanHistory[] = scanResult.rows.map((r) => ({
    completedAt: asString(r[idx["@timestamp"]]),
    scanId: asString(r[idx["gmi.appsec.scan.id"]]) ?? "",
    status: asString(r[idx["gmi.appsec.scan.status"]]),
    findings: asNumber(r[idx["gmi.appsec.findings.total"]]),
    critical: asNumber(r[idx["gmi.appsec.severity.critical"]]),
    high: asNumber(r[idx["gmi.appsec.severity.high"]]),
    newCritical: asNumber(r[idx["gmi.appsec.delta.new.critical"]]),
    newHigh: asNumber(r[idx["gmi.appsec.delta.new.high"]]),
    resolved: asNumber(r[idx["gmi.appsec.delta.resolved.total"]]),
    gate: asString(r[idx["gmi.appsec.gate.result"]]),
  }));

  let findings: AppSecFinding[] = [];
  let findingsError: string | null = null;
  const latestScanId = scans[0]?.scanId;

  if (latestScanId) {
    try {
      const findingResult = await executeEsql(connection, FINDINGS_QUERY(safeName, esqlStringLiteral(latestScanId)));
      const fidx = Object.fromEntries([
        "@timestamp", "gmi.appsec.finding.fingerprint", "gmi.appsec.finding.id", "gmi.appsec.finding.severity",
        "gmi.appsec.finding.kind", "gmi.appsec.finding.title", "gmi.appsec.finding.target",
        "gmi.appsec.finding.status", "package.name", "vulnerability.id",
      ].map((name) => [name, col(findingResult, name)])) as Record<string, number>;

      findings = findingResult.rows.map((r) => ({
        observedAt: asString(r[fidx["@timestamp"]]),
        fingerprint: asString(r[fidx["gmi.appsec.finding.fingerprint"]]) ?? "",
        id: asString(r[fidx["gmi.appsec.finding.id"]]) ?? "",
        severity: asString(r[fidx["gmi.appsec.finding.severity"]]) ?? "UNKNOWN",
        kind: asString(r[fidx["gmi.appsec.finding.kind"]]) ?? "unknown",
        title: asString(r[fidx["gmi.appsec.finding.title"]]) ?? "Untitled finding",
        target: asString(r[fidx["gmi.appsec.finding.target"]]),
        status: asString(r[fidx["gmi.appsec.finding.status"]]),
        package: asString(r[fidx["package.name"]]),
        vulnerabilityId: asString(r[fidx["vulnerability.id"]]),
      }));
    } catch (err) {
      findingsError = err instanceof Error ? err.message : "Could not load findings.";
    }
  }

  return { repository, scans, findings, findingsError };
}
