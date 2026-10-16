import { emptySeverityCounts, sourceSeverities, type CustomerSourceRead, type SourceCveRow } from "./customer-source-read-model";
import { createSpotlightTopFixes } from "./spotlight-top-fixes";

export const SPOTLIGHT_SUMMARY_VERSION = 4;
export type SpotlightVendorScope = { version: 2; tenantId: string | null; mixed: boolean; missingRows: number; rows: number; localPlaceholderRows: number };
export function matchesSpotlightTenant(scope: unknown, tenantId: string, sourceRows: unknown): boolean {
  const value = scope as SpotlightVendorScope | null;
  return /^[a-f0-9]{32}$/i.test(tenantId) && !!value && value.version === 2 &&
    Number.isSafeInteger(value.rows) && Number.isSafeInteger(value.localPlaceholderRows) &&
    value.localPlaceholderRows >= 0 && value.rows > value.localPlaceholderRows &&
    value.rows === Number(sourceRows) && value.missingRows === 0 && value.mixed === false && value.tenantId === tenantId.toLowerCase();
}
export const spotlightSummaryDefinition = { instanceUnit: "spotlight-finding", severityBasis: "source-cvss", suppression: "exclude-confirmed-suppressed" } as const;
export type SpotlightSummary = Extract<CustomerSourceRead, { state: "available" }>["summary"];
export type SummaryInput = {
  source_id: string; company_id: string; cve: string; status: string; id: unknown; cid: unknown; aid: unknown;
  raw_status: unknown; raw_cve: unknown; raw_severity: unknown; score: unknown; suppressed: unknown;
  // Computed by the trusted SQL reader from the exact local placeholder shape.
  local_placeholder?: boolean;
  patch?: Record<string,unknown>;
};
export const summaryLimits = { records: 5_000_000, pairs: 5_000_000, devices: 100_000, cves: 100_000 };
const ranks = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
export function summaryCount(value: unknown): number {
  if (typeof value !== "number" && (typeof value !== "string" || !/^\d+$/.test(value))) throw new Error("Invalid summary count.");
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("Invalid summary count.");
  return n;
}
export function createSpotlightSummaryAccumulator(companyId: string, limits = summaryLimits) {
  for (const key of Object.keys(summaryLimits) as (keyof typeof summaryLimits)[]) {
    if (!Number.isSafeInteger(limits[key]) || limits[key] < 1 || limits[key] > summaryLimits[key]) throw new Error("Invalid summary limits.");
  }
  let scanned = 0, pairs = 0, instances = 0, suppressed = 0, nonCve = 0, unknownSuppression = 0;
  let tenantId: string | null = null, mixed = false, missingRows = 0, localPlaceholderRows = 0;
  const severity = emptySeverityCounts(), devices = new Map<string, number>();
  const cves = new Map<string, SourceCveRow & { deviceKeys: Set<number> }>();
  const topFixes = createSpotlightTopFixes(companyId);
  function add(row: SummaryInput) {
    if (row.company_id !== companyId || !row.source_id) throw new Error("Source row does not match the selected customer.");
    if (++scanned > limits.records) throw new Error("Summary record limit exceeded.");
    // The importer stores {id, unresolved:true} when hydration no longer returns
    // a discovered ID. This is local bookkeeping, not a vendor finding with a
    // missing tenant. It contributes neither findings nor a claimed CID.
    if (row.local_placeholder === true) {
      if (row.id !== row.source_id || row.status !== "closed" || row.cve !== `CS-${row.source_id}` ||
          row.cid != null || row.aid != null || row.raw_status != null || row.raw_cve != null || row.suppressed != null)
        throw new Error("Invalid local Spotlight placeholder evidence.");
      localPlaceholderRows++;
      return;
    }
    // Every actual vendor row still needs scope evidence, including closed,
    // suppressed and non-CVE entries. Do not infer it from displayed findings.
    if (typeof row.cid !== "string" || !/^[a-f0-9]{32}$/i.test(row.cid)) missingRows++;
    else if (tenantId === null) tenantId = row.cid.toLowerCase();
    else if (tenantId !== row.cid.toLowerCase()) mixed = true;
    if (!["open", "reopen"].includes(row.status)) return;
    if (row.suppressed === true) { suppressed++; return; }
    if (!/^CVE-\d{4}-\d{4,}$/.test(row.cve)) { nonCve++; return; }
    if (row.id !== row.source_id || typeof row.raw_cve !== "string" || row.raw_cve.toUpperCase() !== row.cve ||
        typeof row.raw_status !== "string" || !["open", "reopen"].includes(row.raw_status.toLowerCase()) ||
        typeof row.cid !== "string" || !row.cid || typeof row.aid !== "string" || !row.aid) {
      throw new Error("Eligible source finding has incomplete or conflicting identity.");
    }
    const key = JSON.stringify([row.cid, row.aid]);
    if (!devices.has(key)) {
      if (devices.size >= limits.devices) throw new Error("Summary device limit exceeded.");
      devices.set(key, devices.size);
    }
    const supplied = typeof row.raw_severity === "string" ? row.raw_severity.toUpperCase() : "UNKNOWN";
    const rating = sourceSeverities.includes(supplied as SourceCveRow["severity"]) ? supplied as SourceCveRow["severity"] : "UNKNOWN";
    // Same nullable CVSS interpretation as the independent retained-source audit.
    const n = (typeof row.score === "string" && row.score.trim() !== "") || typeof row.score === "number" ? Number(row.score) : NaN;
    const cvss = Number.isFinite(n) && n >= 0 && n <= 10 ? n : null;
    let cve = cves.get(row.cve);
    if (!cve) {
      if (cves.size >= limits.cves) throw new Error("Summary CVE limit exceeded.");
      cve = { cve: row.cve, severity: rating, cvss: null, affectedDevices: 0, sourceInstances: 0, deviceKeys: new Set() };
      cves.set(row.cve, cve);
    }
    const device = devices.get(key)!;
    topFixes.add(row.patch,row.cve,device);
    if (!cve.deviceKeys.has(device)) {
      if (pairs >= limits.pairs) throw new Error("Summary device/CVE limit exceeded.");
      cve.deviceKeys.add(device); cve.affectedDevices++; pairs++;
    }
    if (ranks.indexOf(rating) > ranks.indexOf(cve.severity)) cve.severity = rating;
    if (cvss !== null) cve.cvss = cve.cvss === null ? cvss : Math.max(cve.cvss, cvss);
    cve.sourceInstances++; instances++; severity[rating]++;
    if (row.suppressed !== false) unknownSuppression++;
  }
  function finish() {
    const unique = emptySeverityCounts();
    const rows = [...cves.values()].map(({ deviceKeys, ...row }) => { unique[row.severity]++; return row; });
    rows.sort((a,b) => ranks.indexOf(b.severity)-ranks.indexOf(a.severity) || b.affectedDevices-a.affectedDevices || (a.cve<b.cve ? -1 : a.cve>b.cve ? 1 : 0));
    const summary: SpotlightSummary = { sourceInstances: instances, deviceCveFindings: pairs, uniqueCves: cves.size, affectedDevices: devices.size,
      inventoryDevices: null, unknownSuppressionInstances: unknownSuppression, excludedSuppressedInstances: suppressed, excludedNonCveInstances: nonCve,
      severity: { sourceInstances: { ...severity }, uniqueCves: unique } };
    const vendorScope: SpotlightVendorScope = { version: 2, tenantId: mixed ? null : tenantId, mixed, missingRows, rows: scanned, localPlaceholderRows };
    return { scanned, summary, rows, vendorScope, topFixes: topFixes.finish() };
  }
  return { add, finish, get scanned() { return scanned; } };
}

// Reconcile small saved CVE aggregates, never the raw finding table, on page reads.
export function validateSpotlightSummary(summary: SpotlightSummary, aggregates: Record<string, unknown>[]) {
  const instanceSeverity = emptySeverityCounts(), cveSeverity = emptySeverityCounts();
  let cves = 0, pairs = 0, instances = 0;
  for (const row of aggregates) {
    const severity = row.severity as SourceCveRow["severity"];
    if (!sourceSeverities.includes(severity)) throw new Error("Invalid summary severity.");
    const n = summaryCount(row.cves), p = summaryCount(row.devices), i = summaryCount(row.findings);
    if (p < n || i < p) throw new Error("Inconsistent summary CVE counts.");
    cveSeverity[severity] = n; cves += n; pairs += p; instances += i;
  }
  // Instance severities need not match each CVE's highest severity distribution.
  for (const key of sourceSeverities) instanceSeverity[key] = summaryCount(summary.severity.sourceInstances[key]);
  if (Object.keys(summary.severity.sourceInstances).length !== sourceSeverities.length ||
      Object.keys(summary.severity.uniqueCves).length !== sourceSeverities.length ||
      cves !== summaryCount(summary.uniqueCves) || pairs !== summaryCount(summary.deviceCveFindings) || instances !== summaryCount(summary.sourceInstances) ||
      Object.values(instanceSeverity).reduce((a,b) => a+b,0) !== instances ||
      sourceSeverities.some(key => summaryCount(summary.severity.uniqueCves[key]) !== cveSeverity[key]) ||
      summaryCount(summary.affectedDevices) > pairs || (instances > 0 && summary.affectedDevices === 0) ||
      summary.inventoryDevices !== null || summaryCount(summary.unknownSuppressionInstances) > instances) throw new Error("Inconsistent saved summary.");
  summaryCount(summary.excludedSuppressedInstances); summaryCount(summary.excludedNonCveInstances);
}
