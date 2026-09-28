import type { Finding, InventoryAsset, Scan } from "./types";

export type SourceActivity = {
  source: string;
  evidence: "scan" | "finding" | "inventory" | "enrichment";
  scanCount: number;
  completedCount: number;
  runningCount: number;
  failedCount: number;
  openObservations: number;
  inventoryAssets: number;
  lastObservedAt: string | null;
};

const open = (status: Finding["status"]) => status === "Open" || status === "In Remediation";
const later = (current: string | null, candidate: string | null | undefined) =>
  candidate && (!current || candidate > current) ? candidate : current;

export function recordVulnersEnrichment(
  current: Finding["enrichments"], observedAt: string,
): NonNullable<Finding["enrichments"]> {
  const existing = current?.filter(item => item.source !== "vulners") ?? [];
  const previous = current?.find(item => item.source === "vulners")?.observedAt;
  return [...existing, { source: "vulners", observedAt: previous && previous > observedAt ? previous : observedAt }];
}

export function buildSourceActivity(companyId: string, scans: Scan[], findings: Finding[], assets: InventoryAsset[]): SourceActivity[] {
  const rows = new Map<string, SourceActivity>();
  const row = (source: string, evidence: SourceActivity["evidence"]) => {
    const existing = rows.get(source);
    if (existing) {
      if (evidence === "scan" || (evidence === "finding" && existing.evidence !== "scan")) existing.evidence = evidence;
      return existing;
    }
    const created: SourceActivity = { source, evidence, scanCount: 0, completedCount: 0,
      runningCount: 0, failedCount: 0, openObservations: 0, inventoryAssets: 0, lastObservedAt: null };
    rows.set(source, created);
    return created;
  };
  for (const scan of scans) {
    if (scan.companyId !== companyId) continue;
    const item = row(scan.connector, "scan");
    item.scanCount++;
    if (scan.status === "Completed") {
      item.completedCount++;
      item.lastObservedAt = later(item.lastObservedAt, scan.completedAt);
    } else if (scan.status === "Failed") item.failedCount++;
    else if (scan.status === "Running" || scan.status === "Queued" || scan.status === "Paused") item.runningCount++;
  }
  for (const finding of findings) {
    if (finding.companyId !== companyId) continue;
    for (const source of new Set(finding.seenBy?.length ? finding.seenBy : [finding.connector])) {
      const item = row(source, "finding");
      if (open(finding.status)) item.openObservations++;
      item.lastObservedAt = later(item.lastObservedAt, finding.lastSeen);
    }
    for (const enrichment of finding.enrichments ?? []) {
      const item = row(enrichment.source, "enrichment");
      item.lastObservedAt = later(item.lastObservedAt, enrichment.observedAt);
    }
  }
  for (const asset of assets) {
    if (asset.companyId !== companyId || asset.source === "inferred") continue;
    const item = row(asset.source, "inventory");
    item.inventoryAssets++;
    item.lastObservedAt = later(item.lastObservedAt, asset.lastSynced);
  }
  return [...rows.values()].sort((a, b) => b.openObservations - a.openObservations || b.scanCount - a.scanCount || a.source.localeCompare(b.source));
}
