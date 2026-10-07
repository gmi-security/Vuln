import { elasticJsonRequest, type ElasticConnection } from "./elastic-query-client";
import type { Finding } from "./types";

// A dedicated Elasticsearch index/stream for Nessus + Vulners-bridge
// findings, separate from both the AppSec CI telemetry streams
// (gmi-appsec-*, fed by CI, org-wide, no tenant scoping) and the customer-
// reporting dashboard's admin-configured connection (ElasticQueryDashboard,
// which has neither Nessus nor Vulners wired in and carries real tenant-
// ownership constraints per docs/reporting-release-gate.md). This is
// intentionally its own, simpler thing: plain scanner telemetry, mirroring
// how AppSec already reports Trivy data, with no customer-facing binding.
export function scannerElasticConfig(): ElasticConnection | null {
  // Defaults to the same cluster AppSec already uses (one less credential to
  // provision) -- override with SCANNER_ELASTIC_URL/_API_KEY for a separate
  // deployment if that's ever wanted.
  const endpoint = (process.env.SCANNER_ELASTIC_URL ?? process.env.APPSEC_ELASTIC_URL)?.trim();
  const apiKey = (process.env.SCANNER_ELASTIC_API_KEY ?? process.env.APPSEC_ELASTIC_API_KEY)?.trim();
  if (!endpoint || !apiKey) return null;
  return { endpoint, apiKey };
}

// Separate indices per source rather than one shared index -- each connector
// has its own event shape/volume/retention profile in practice, and keeping
// them apart means an index pattern, dashboard, or API key can target just
// one without a filter clause. gmi.scanner.source (below) still tags every
// document, so a query that genuinely wants both at once can still do
// `FROM gmi-nessus-findings,gmi-vulners-findings`.
const SCANNER_STREAM_BY_CONNECTOR: Record<"nessus" | "vulners", string> = {
  nessus: process.env.SCANNER_ELASTIC_NESSUS_STREAM?.trim() || "gmi-nessus-findings",
  vulners: process.env.SCANNER_ELASTIC_VULNERS_STREAM?.trim() || "gmi-vulners-findings",
};

const EXPORTED_CONNECTORS = new Set<Finding["connector"]>(["nessus", "vulners"]);

export function isScannerExportable(finding: Finding): boolean {
  return EXPORTED_CONNECTORS.has(finding.connector);
}

export function scannerStreamFor(connector: Finding["connector"]): string | undefined {
  return SCANNER_STREAM_BY_CONNECTOR[connector as "nessus" | "vulners"];
}

export function scannerStreams(): string[] {
  return Object.values(SCANNER_STREAM_BY_CONNECTOR);
}

export type ScannerFindingDoc = {
  "@timestamp": string;
  "gmi.scanner.source": string;
  "gmi.scanner.finding.id": string;
  "gmi.scanner.company.id": string;
  "gmi.scanner.company.name": string;
  "gmi.scanner.finding.severity": string;
  "gmi.scanner.finding.cvss": number;
  "gmi.scanner.finding.cve": string;
  "gmi.scanner.finding.title": string;
  "gmi.scanner.finding.status": string;
  "gmi.scanner.finding.asset": string;
  "gmi.scanner.finding.first_seen": string;
  "gmi.scanner.finding.resolved_at": string | null;
  "gmi.scanner.finding.exploit_available": boolean;
  "gmi.scanner.scan.id": string;
};

// @timestamp is lastSeen (not firstSeen): this index is overwritten by id on
// every export pass, so @timestamp should reflect when this document's data
// was last true, matching how Elastic dashboards expect to sort/filter on
// recency.
export function scannerFindingDoc(f: Finding): ScannerFindingDoc {
  return {
    "@timestamp": f.lastSeen,
    "gmi.scanner.source": f.connector,
    "gmi.scanner.finding.id": f.id,
    "gmi.scanner.company.id": f.companyId,
    "gmi.scanner.company.name": f.companyName,
    "gmi.scanner.finding.severity": f.severity,
    "gmi.scanner.finding.cvss": f.cvss,
    "gmi.scanner.finding.cve": f.cve,
    "gmi.scanner.finding.title": f.title,
    "gmi.scanner.finding.status": f.status,
    "gmi.scanner.finding.asset": f.asset,
    "gmi.scanner.finding.first_seen": f.firstSeen,
    "gmi.scanner.finding.resolved_at": f.resolvedAt,
    "gmi.scanner.finding.exploit_available": f.exploitAvailable,
    "gmi.scanner.scan.id": f.scanId,
  };
}

// Elasticsearch `_bulk` NDJSON body: one action line + one source line per
// document. Indexing (not creating) by the finding's own id makes this
// idempotent -- re-running it (the scheduler does, every few minutes) just
// overwrites each document with current state, so a status change or
// rescore on an existing finding is picked up for free with no separate
// dirty-tracking, and a lost/out-of-sync document self-heals on the next
// pass.
export function scannerBulkBody(findings: Finding[]): string {
  const lines: string[] = [];
  for (const f of findings) {
    const stream = scannerStreamFor(f.connector);
    if (!stream) continue; // not an exported connector -- caller should have filtered already
    lines.push(JSON.stringify({ index: { _index: stream, _id: f.id } }));
    lines.push(JSON.stringify(scannerFindingDoc(f)));
  }
  return lines.length ? lines.join("\n") + "\n" : "";
}

// Unlike the AppSec streams (gmi-appsec-scans/gmi-appsec-findings, created
// ahead of time by whoever set those up, outside this app), nothing creates
// gmi-nessus-findings/gmi-vulners-findings for us -- and a plain `_bulk`
// "index" action doesn't reliably auto-create a brand new index on every
// Elasticsearch deployment (confirmed in production: an ES|QL query against
// one came back "Unknown index" even with the export wired up and real
// findings to send). A plain PUT of each index is idempotent and needs no
// template, unlike a data stream, so this doesn't depend on anyone
// configuring anything in Kibana. Cached per process so this doesn't repeat
// every 5-minute export pass once it succeeds; a failed attempt (not just
// "already exists") retries next time rather than being remembered as done.
const scannerIndexesEnsured = new Set<string>();

async function ensureScannerIndex(connection: ElasticConnection, stream: string): Promise<void> {
  if (scannerIndexesEnsured.has(stream)) return;
  try {
    await elasticJsonRequest(connection, `/${stream}`, "PUT", {});
    scannerIndexesEnsured.add(stream);
  } catch (err) {
    if (err instanceof Error && /resource_already_exists_exception/i.test(err.message)) {
      scannerIndexesEnsured.add(stream);
      return;
    }
    throw err;
  }
}

export type ScannerExportResult = { indexed: number; errors: number; firstError: string | null };

export async function indexScannerFindings(findings: Finding[]): Promise<ScannerExportResult> {
  const eligible = findings.filter(isScannerExportable);
  if (!eligible.length) return { indexed: 0, errors: 0, firstError: null };
  const connection = scannerElasticConfig();
  if (!connection) throw new Error("Scanner Elastic connection is not configured (set SCANNER_ELASTIC_URL/_API_KEY or APPSEC_ELASTIC_URL/_API_KEY).");

  const streamsNeeded = new Set(eligible.map((f) => scannerStreamFor(f.connector)).filter((s): s is string => Boolean(s)));
  for (const stream of streamsNeeded) await ensureScannerIndex(connection, stream);
  const { body } = await elasticJsonRequest(connection, "/_bulk", "POST", undefined, { ndjson: scannerBulkBody(eligible) });
  // `_bulk` returns HTTP 200 even when individual items fail -- per-item
  // errors live in the response body, not the status code.
  const items = Array.isArray(body.items) ? body.items : [];
  let errors = 0;
  let firstError: string | null = null;
  for (const item of items) {
    const action = (item as Record<string, unknown>)?.index as { error?: { reason?: unknown } } | undefined;
    if (action?.error) {
      errors += 1;
      if (!firstError) firstError = typeof action.error.reason === "string" ? action.error.reason : "Unknown bulk index error.";
    }
  }
  return { indexed: eligible.length - errors, errors, firstError };
}
