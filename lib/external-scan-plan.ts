import { scannerExactTargetKey } from "./scanner-target-scope";

// A preview of recurring Nessus-to-Greenbone scans. No scan initiation here.
export type ExternalScheduleEntry = {
  nessusScanId: number;
  scanName: string;
  enabled: boolean;
  nextOccurrence: string | null;
  offsetNextTrigger: string | null;
};
export type ExternalScheduleMatrix = {
  generatedAt: string;
  companies: Array<{ companyId: string; companyName: string; scans: ExternalScheduleEntry[] }>;
};
export type ExternalApprovedRoute = { companyId: string; provider: string; targets: string[] };
export type ExternalScanCandidate = {
  companyId: string;
  companyName: string;
  target: string;
  nessusScanId: number;
  nessusScanName: string;
  nominalOffsetAt: string;
  state: "review-required";
};
export type ExternalScanPlan = {
  mode: "preview-only";
  generatedAt: string;
  launchesEnabled: false;
  routeStatus: "unavailable" | "reviewed";
  candidates: ExternalScanCandidate[];
  blocked: Array<{ companyId: string; reason: string }>;
};

/**
 * Historic Nessus findings and observed IPs are not scan authorization.
 * A candidate requires one reviewed Vulners route, an exact host/IP and
 * an enabled upcoming Nessus schedule. Even a candidate is NOT executable:
 * future dispatch must confirm Nessus actually finished its run, an approved
 * window is open and global scanner capacity is available.
 */
export function buildExternalScanPlan(
  matrix: ExternalScheduleMatrix,
  routes: readonly ExternalApprovedRoute[] | null,
): ExternalScanPlan {
  const out: ExternalScanPlan = {
    mode: "preview-only", generatedAt: matrix.generatedAt, launchesEnabled: false,
    routeStatus: routes === null ? "unavailable" : "reviewed", candidates: [], blocked: [],
  };
  if (routes === null) {
    out.blocked.push({ companyId: "*", reason: "Reviewed Vulners customer routing is not enabled. No legacy fallback." });
    return out;
  }
  const byCompany = new Map<string, ExternalApprovedRoute[]>();
  const owners = new Map<string, string>();
  const contested = new Set<string>();
  for (const route of routes) {
    if (route.provider !== "vulners") continue;
    const existing = byCompany.get(route.companyId) ?? [];
    existing.push(route);
    byCompany.set(route.companyId, existing);
    for (const target of route.targets ?? []) {
      try {
        const key = scannerExactTargetKey(target);
        const previous = owners.get(key);
        if (previous && previous !== route.companyId) contested.add(key);
        else owners.set(key, route.companyId);
      } catch { /* invalid scope is rejected when candidates are built */ }
    }
  }
  const now = Date.parse(matrix.generatedAt);
  if (!Number.isFinite(now)) {
    out.blocked.push({ companyId: "*", reason: "Invalid schedule matrix timestamp." });
    return out;
  }
  const seen = new Set<string>();
  for (const company of matrix.companies) {
    const matches = byCompany.get(company.companyId) ?? [];
    if (matches.length !== 1) {
      out.blocked.push({ companyId: company.companyId, reason: matches.length ? "Ambiguous approved customer route." : "No approved Vulners route." });
      continue;
    }
    const route = matches[0];
    if (!route.targets?.length || route.targets.length > 100) {
      out.blocked.push({ companyId: company.companyId, reason: "Approved scope is empty or too large." });
      continue;
    }
    const normalized = new Map<string, string>();
    let invalid = false;
    for (const target of route.targets) {
      try {
        const key = scannerExactTargetKey(target);
        if (contested.has(key)) { invalid = true; break; }
        normalized.set(key, target);
      } catch { invalid = true; break; }
    }
    if (invalid) {
      out.blocked.push({ companyId: company.companyId, reason: "Invalid or cross-customer overlapping approved target." });
      continue;
    }
    // Several Nessus schedules must not multiply jobs for the same host.
    const upcoming = company.scans.filter(s => s.enabled && Number.isSafeInteger(s.nessusScanId) && s.nessusScanId > 0 &&
      s.nextOccurrence && s.offsetNextTrigger && Number.isFinite(Date.parse(s.nextOccurrence)) &&
      Number.isFinite(Date.parse(s.offsetNextTrigger)) && Date.parse(s.offsetNextTrigger) > now &&
      Math.abs(Date.parse(s.offsetNextTrigger) - Date.parse(s.nextOccurrence) - 3_600_000) < 1000)
      .sort((a, b) => Date.parse(a.offsetNextTrigger!) - Date.parse(b.offsetNextTrigger!));
    if (!upcoming.length) {
      out.blocked.push({ companyId: company.companyId, reason: "No valid enabled future Nessus recurrence." });
      continue;
    }
    const next = upcoming[0];
    for (const [key, target] of normalized) {
      const dedup = company.companyId + ":" + key;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      out.candidates.push({ companyId: company.companyId, companyName: company.companyName,
        target, nessusScanId: next.nessusScanId, nessusScanName: next.scanName,
        nominalOffsetAt: next.offsetNextTrigger!, state: "review-required" });
    }
  }
  out.candidates.sort((a, b) => a.nominalOffsetAt.localeCompare(b.nominalOffsetAt) ||
    a.companyId.localeCompare(b.companyId) || a.target.localeCompare(b.target));
  return out;
}
