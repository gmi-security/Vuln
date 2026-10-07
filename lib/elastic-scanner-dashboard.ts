import { executeEsql } from "./elastic-query-client";
import { DashboardError, type QueryResult } from "./elastic-dashboard";
import { scannerElasticConfig, scannerStreams } from "./elastic-scanner-export";

// Read side for the Nessus/Vulners scanner telemetry exported by
// lib/elastic-scanner-export.ts -- mirrors lib/elastic-appsec.ts's shape
// (same executeEsql/DashboardError plumbing), but reads the
// gmi-nessus-findings/gmi-vulners-findings indices instead of the AppSec
// CI streams. No tenant/customer-ownership binding here, same as AppSec --
// this is plain scanner telemetry, not the customer-reporting surface.

function col(result: QueryResult, name: string): number {
  const i = result.columns.findIndex((c) => c.name === name);
  if (i < 0) throw new DashboardError(`Scanner dashboard query is missing the "${name}" column.`);
  return i;
}

function asNumber(v: string | number | boolean | null): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function asString(v: string | number | boolean | null): string {
  return typeof v === "string" ? v : "";
}

const FROM_CLAUSE = `FROM ${scannerStreams().join(",")}`;

export type ScannerSummary = {
  totalFindings: number;
  nessusFindings: number;
  vulnersFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  exploitAvailable: number;
};

const SEVERITY_SOURCE_QUERY = `${FROM_CLAUSE}
| STATS count = COUNT(*) BY \`gmi.scanner.source\`, \`gmi.scanner.finding.severity\`
| LIMIT 100`;

const EXPLOIT_QUERY = `${FROM_CLAUSE}
| WHERE \`gmi.scanner.finding.exploit_available\` == true
| STATS count = COUNT(*)`;

export async function fetchScannerSummary(): Promise<ScannerSummary> {
  const connection = scannerElasticConfig();
  if (!connection) throw new DashboardError("Scanner Elastic connection is not configured.");

  const bySeverity = await executeEsql(connection, SEVERITY_SOURCE_QUERY);
  const idx = {
    count: col(bySeverity, "count"),
    source: col(bySeverity, "gmi.scanner.source"),
    severity: col(bySeverity, "gmi.scanner.finding.severity"),
  };

  const summary: ScannerSummary = {
    totalFindings: 0, nessusFindings: 0, vulnersFindings: 0,
    critical: 0, high: 0, medium: 0, low: 0, exploitAvailable: 0,
  };
  for (const row of bySeverity.rows) {
    const count = asNumber(row[idx.count]);
    const source = asString(row[idx.source]);
    const severity = asString(row[idx.severity]);
    summary.totalFindings += count;
    if (source === "nessus") summary.nessusFindings += count;
    else if (source === "vulners") summary.vulnersFindings += count;
    if (severity === "Critical") summary.critical += count;
    else if (severity === "High") summary.high += count;
    else if (severity === "Medium") summary.medium += count;
    else if (severity === "Low") summary.low += count;
  }

  // A separate call rather than folding into the query above: ES|QL's STATS
  // doesn't uniformly support a conditional COUNT(*) WHERE expression across
  // every Elasticsearch version this cluster might be running, and this
  // number is a nice-to-have, not core -- never let it take down the rest
  // of the summary.
  try {
    const exploit = await executeEsql(connection, EXPLOIT_QUERY);
    summary.exploitAvailable = asNumber(exploit.rows[0]?.[col(exploit, "count")] ?? 0);
  } catch {
    summary.exploitAvailable = 0;
  }

  return summary;
}

export type ScannerCompanyRow = {
  companyId: string;
  companyName: string;
  nessus: number;
  vulners: number;
  total: number;
};

const BY_COMPANY_QUERY = `${FROM_CLAUSE}
| STATS count = COUNT(*) BY \`gmi.scanner.company.id\`, \`gmi.scanner.company.name\`, \`gmi.scanner.source\`
| LIMIT 1000`;

export async function fetchScannerCompanyRows(): Promise<ScannerCompanyRow[]> {
  const connection = scannerElasticConfig();
  if (!connection) throw new DashboardError("Scanner Elastic connection is not configured.");

  const result = await executeEsql(connection, BY_COMPANY_QUERY);
  const idx = {
    count: col(result, "count"),
    id: col(result, "gmi.scanner.company.id"),
    name: col(result, "gmi.scanner.company.name"),
    source: col(result, "gmi.scanner.source"),
  };

  const byCompany = new Map<string, ScannerCompanyRow>();
  for (const row of result.rows) {
    const companyId = asString(row[idx.id]);
    const companyName = asString(row[idx.name]);
    const source = asString(row[idx.source]);
    const count = asNumber(row[idx.count]);
    const existing = byCompany.get(companyId) ?? { companyId, companyName, nessus: 0, vulners: 0, total: 0 };
    if (source === "nessus") existing.nessus += count;
    else if (source === "vulners") existing.vulners += count;
    existing.total += count;
    byCompany.set(companyId, existing);
  }

  return Array.from(byCompany.values()).sort((a, b) => b.total - a.total);
}
