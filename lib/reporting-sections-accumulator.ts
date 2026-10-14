import type { Company, Finding, InventoryAsset, Scan, Severity } from "./types";
import type { CustomerReportingModel } from "./reporting-customer-model";
import type { SourceActivity } from "./reporting-source-activity";
import { reportingFindingClass } from "./reporting-metrics";

// Derived reporting only. Consume normalized platform records in persisted map
// order, not raw vendor rows. Keep bounded lists rather than an entire estate.
export function createReportingSectionsAccumulator(company: Pick<Company, "id" | "name">) {
  const severities: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
  const bySeverity = Object.fromEntries(severities.map(s => [s, 0])) as Record<Severity, number>;
  const sources = new Map<string, SourceActivity>();
  const evidenceRank = { inventory: 0, enrichment: 1, finding: 2, scan: 3 };
  const source = (name: string, evidence: SourceActivity["evidence"]) => {
    let row = sources.get(name);
    if (!row) {
      row = { source: name, evidence, scanCount: 0, completedCount: 0, runningCount: 0,
        failedCount: 0, openObservations: 0, inventoryAssets: 0, lastObservedAt: null };
      sources.set(name, row);
    } else if (evidenceRank[evidence] > evidenceRank[row.evidence]) row.evidence = evidence;
    return row;
  };
  const observed = (row: SourceActivity, value: string | null | undefined) => {
    if (value && (!row.lastObservedAt || value > row.lastObservedAt)) row.lastObservedAt = value;
  };
  type Ranked = { row: CustomerReportingModel["priorityRows"][number]; cvss: number };
  const priority: Ranked[] = [], exposure: Ranked[] = [], web: Ranked[] = [];
  const top = (rows: Ranked[], finding: Finding, limit: number) => {
    const next: Ranked = { cvss: finding.cvss, row: { id: finding.id, cve: finding.cve, title: finding.title,
      asset: finding.asset, severity: finding.severity, realRisk: finding.realRisk, status: finding.status,
      lastSeen: finding.lastSeen, connectors: [...(finding.seenBy?.length ? finding.seenBy : [finding.connector])] } };
    // listFindings supplies risk/CVSS order to the current report, including
    // the exposure and web sections. Exact ties retain persisted map order.
    let index = rows.findIndex(value => value.row.realRisk < next.row.realRisk ||
      (value.row.realRisk === next.row.realRisk && value.cvss < next.cvss));
    if (index < 0) index = rows.length;
    if (index < limit) { rows.splice(index, 0, next); if (rows.length > limit) rows.pop(); }
  };
  const recentScans: CustomerReportingModel["recentScans"] = [];
  const assetSources = new Map<InventoryAsset["source"], { count: number; identifier: string; order: number }>();
  let records = 0, scanTotal = 0, inventoryCount = 0, open = 0, kev = 0, exploitable = 0, cveOpen = 0;
  let priorityTotal = 0, exposureTotal = 0, webTotal = 0, authoritativeFindingCount = 0;
  let vulnerabilityAssessed = false, webAssessed = false;
  const requireValue = (ok: unknown, message: string) => { if (!ok) throw new Error(message); };
  return {
    finding(finding: Finding) {
      requireValue(finding.companyId === company.id, "Reporting finding customer mismatch");
      requireValue(severities.includes(finding.severity) && Number.isFinite(finding.realRisk) &&
        Number.isFinite(finding.cvss) && typeof finding.connector === "string" &&
        ["Open", "In Remediation", "Resolved", "Risk Accepted", "False Positive"].includes(finding.status), "Invalid reporting finding");
      records++;
      const isOpen = finding.status === "Open" || finding.status === "In Remediation";
      for (const connector of new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector])) {
        const row = source(connector, "finding"); if (isOpen) row.openObservations++; observed(row, finding.lastSeen);
      }
      for (const item of finding.enrichments ?? []) observed(source(item.source, "enrichment"), item.observedAt);
      if (!isOpen) return;
      const kind = reportingFindingClass(finding.connector);
      if (kind === "osint") { exposureTotal++; top(exposure, finding, 10); return; }
      open++; bySeverity[finding.severity]++;
      if (finding.kev) kev++; if (finding.exploitAvailable) exploitable++;
      if (/^CVE-\d{4}-\d{4,19}$/i.test(finding.cve)) cveOpen++;
      if (finding.assetSource === "tidal" || finding.assetSource === "manual") authoritativeFindingCount++;
      if (kind === "pentest") { webTotal++; top(web, finding, 10); }
      else { priorityTotal++; top(priority, finding, 25); }
    },
    scan(scan: Scan) {
      requireValue(scan.companyId === company.id && typeof scan.createdAt === "string", "Invalid reporting scan scope or date");
      scanTotal++;
      const row = source(scan.connector, "scan"); row.scanCount++;
      if (scan.status === "Completed") {
        row.completedCount++; observed(row, scan.completedAt);
        if (reportingFindingClass(scan.connector) === "vuln") vulnerabilityAssessed = true;
        if (reportingFindingClass(scan.connector) === "pentest") webAssessed = true;
      } else if (scan.status === "Failed") row.failedCount++;
      else if (["Running", "Queued", "Paused"].includes(scan.status)) row.runningCount++;
      const item = { id: scan.id, name: scan.name, connector: scan.connector, status: scan.status,
        createdAt: scan.createdAt, completedAt: scan.completedAt, findingsCount: scan.findingsCount, hostsScanned: scan.hostsScanned };
      // listScans orders equal creation times in reverse map order.
      let index = recentScans.findIndex(value => scan.createdAt.localeCompare(value.createdAt) >= 0);
      if (index < 0) index = recentScans.length;
      if (index < 12) { recentScans.splice(index, 0, item); if (recentScans.length > 12) recentScans.pop(); }
    },
    asset(asset: InventoryAsset) {
      requireValue(asset.companyId === company.id && typeof asset.identifier === "string", "Invalid reporting asset scope or identifier");
      inventoryCount++;
      const first = assetSources.get(asset.source);
      if (first) { first.count++; if (asset.identifier.localeCompare(first.identifier) < 0) { first.identifier = asset.identifier; first.order = inventoryCount; } }
      else assetSources.set(asset.source, { count: 1, identifier: asset.identifier, order: inventoryCount });
      if (asset.source !== "inferred") {
        const row = source(asset.source, "inventory"); row.inventoryAssets++; observed(row, asset.lastSynced);
      }
    },
    finish(history: { ts: string; data: unknown }[]): { records: number; model: CustomerReportingModel } {
      const assessed = open > 0 || vulnerabilityAssessed;
      return { records, model: {
        company: { id: company.id, name: company.name },
        metrics: { vulnerabilities: { open, critical: bySeverity.Critical, high: bySeverity.High, kev, exploitable, cveOpen,
          bySeverity: { ...bySeverity }, assessed }, attackSurface: { open: exposureTotal }, webTesting: { open: webTotal, assessed: webAssessed } },
        assessmentState: assessed ? "assessed" : "unassessed",
        sourceActivity: [...sources.values()].map(row => ({ ...row })).sort((a, b) => b.openObservations - a.openObservations || b.scanCount - a.scanCount || a.source.localeCompare(b.source)),
        priorityTotal, priorityRows: priority.map(item => item.row), scanTotal, recentScans: [...recentScans],
        assets: { inventoryCount, authoritativeFindingCount,
          contextCoveragePercent: open ? Math.round(authoritativeFindingCount / open * 100) : null, scanCoveragePercent: null,
          sourceCounts: [...assetSources].sort((a, b) => a[1].identifier.localeCompare(b[1].identifier) || a[1].order - b[1].order)
            .map(([source, value]) => ({ source, count: value.count })) },
        attackSurfaceRows: exposure.map(item => item.row), webTestingRows: web.map(item => item.row),
        history: history.filter(row => row && typeof row.ts === "string" && typeof row.data === "object" && row.data !== null)
          .map(row => ({ ts: row.ts, open: typeof (row.data as { totalOpen?: unknown }).totalOpen === "number" ? (row.data as { totalOpen: number }).totalOpen : null })),
        legacyHistory: [],
      } };
    },
  };
}
