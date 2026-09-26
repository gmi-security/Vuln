import type { ConnectorId, Severity } from "@/lib/types";

// Cross-connector correlation: the same (company, CVE, asset) reported by
// more than one scanner is one real vulnerability, not one per scanner. Two
// scanners agreeing corroborates it; mergeFindingAssessment folds the report
// into the existing record instead of creating a duplicate row, tracking
// every connector that has seen it and keeping the most severe/complete
// assessment across all of them — under-reporting risk is the dangerous
// failure mode, so a stricter scanner's read is never masked by a looser
// one. Scoped to the connectors that report "this host has this CVE" facts;
// web/app/recon tools (Burp, Nmap, SpiderFoot, ZAP, Artemis) report
// scanner-specific test results instead and stay on their own dedupe.
export const CORRELATED_CONNECTORS = new Set<ConnectorId>([
  "crowdstrike",
  "nessus",
  "defender",
  "vulners",
  "qualys",
]);

// Resolves a scanner-reported asset string to the inventory's stable asset
// id when the asset is known, so two connectors watching the same device
// from different vantage points — an external scanner's public IP, an
// agent's internal hostname — correlate on the same underlying asset instead
// of two unrelated strings. Falls back to the normalized raw string for
// assets the inventory doesn't have yet (e.g. discovered only by the scan
// itself).
export function normalizeIdentifier(id: string): string {
  return id.trim().toLowerCase().replace(/\.+$/, "");
}
export function identityKey(companyId: string, id: string): string {
  return `${companyId}::${normalizeIdentifier(id)}`;
}

// Union-find with path compression over identityKey()s. A device's known
// identifiers (hostname, internal IP, external IP, ...) get linked together
// by linkIdentities whenever a connector reports more than one of them for
// the same finding; resolveIdentity then maps any one of them to the same
// group regardless of which identifier a DIFFERENT connector used.
export function findIdentityRoot(aliases: Map<string, string>, key: string): string {
  let root = key;
  const path: string[] = [];
  while (aliases.has(root)) {
    path.push(root);
    const next = aliases.get(root)!;
    if (next === root) break;
    root = next;
  }
  for (const step of path) if (step !== root) aliases.set(step, root);
  return root;
}
export function resolveIdentity(aliases: Map<string, string>, companyId: string, id: string): string {
  return findIdentityRoot(aliases, identityKey(companyId, id));
}
// Links every non-empty identifier in `ids` as the same device, company-
// scoped so two customers' devices are never merged just for sharing an IP.
// Safe to call every import — already-linked identifiers are a no-op.
export function linkIdentities(aliases: Map<string, string>, companyId: string, ids: (string | undefined | null)[]): void {
  const keys = [...new Set(ids.filter((id): id is string => Boolean(id?.trim())).map((id) => identityKey(companyId, id)))];
  if (keys.length < 2) return;
  const canonical = findIdentityRoot(aliases, keys[0]);
  for (const key of keys) {
    const root = findIdentityRoot(aliases, key);
    if (root !== canonical) aliases.set(root, canonical);
  }
}

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0,
};

export interface FindingAssessment {
  connector: ConnectorId;
  cvss: number;
  cvssV3: number;
  cvssV2: number;
  vpr: number;
  epss: number;
  exploitAvailable: boolean;
  severity: Severity;
  lastSeen: string;
}

// Folds a corroborating scanner's read into an existing assessment, in
// place, taking the worst case (most severe/complete) field by field so a
// weaker or later report never masks a stronger one already on record.
export function mergeFindingAssessment(
  existing: FindingAssessment & { seenBy?: ConnectorId[] },
  incoming: FindingAssessment,
): void {
  existing.seenBy = [...new Set([...(existing.seenBy ?? [existing.connector]), incoming.connector])];
  existing.lastSeen = incoming.lastSeen;
  if (incoming.cvss > existing.cvss) existing.cvss = incoming.cvss;
  if (incoming.cvssV3 > existing.cvssV3) existing.cvssV3 = incoming.cvssV3;
  if (incoming.cvssV2 > existing.cvssV2) existing.cvssV2 = incoming.cvssV2;
  if (incoming.vpr > existing.vpr) existing.vpr = incoming.vpr;
  if (incoming.epss > existing.epss) existing.epss = incoming.epss;
  if (incoming.exploitAvailable) existing.exploitAvailable = true;
  if (SEVERITY_RANK[incoming.severity] > SEVERITY_RANK[existing.severity]) existing.severity = incoming.severity;
}
