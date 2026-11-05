import { scannerExactTargetKey, scannerTargetMatcher } from "./scanner-target-scope";

// Read-only comparison of independently approved source *scopes*.
// This does not prove configured Nessus per-scan targets, completed Nessus
// coverage, a Greenbone launch, or a completed Greenbone result.
type Route = { companyId: string; provider: string; targets: string[]; sourceScope?: string };
type ScopeStatus = "approved-targets-match" | "approved-targets-differ" | "unverifiable";
export type ApprovedTargetParity = {
  mode: "approved-scopes-only";
  executedScanParityVerified: false;
  nessusRoutesAvailable: boolean;
  vulnersRoutesAvailable: boolean;
  companies: Array<{
    companyId: string;
    status: ScopeStatus;
    nessusFolderId: string | null;
    nessusExactCount: number;
    vulnersExactCount: number;
    matchingExactCount: number;
    missingFromVulners: string[];
    notExactNessusTargets: string[];
    nessusNetworksRequiringExpansionReview: string[];
    problems: string[];
  }>;
  matchedApprovedScopeCount: number;
  unresolvedCompanyCount: number;
};

function normalized(values: string[], permitNetworks: boolean) {
  const exact = new Map<string, string>();
  const networks: string[] = [];
  const problems: string[] = [];
  if (!Array.isArray(values) || values.length === 0 || values.length > 100) {
    problems.push("Missing or oversized approved target scope.");
    return { exact, networks, problems };
  }
  for (const value of values) {
    try {
      const key = scannerExactTargetKey(value);
      if (exact.has(key)) problems.push("Duplicate approved target identity.");
      else exact.set(key, value);
    } catch {
      if (!permitNetworks) {
        problems.push("Invalid or non-exact Vulners target.");
        continue;
      }
      try {
        scannerTargetMatcher([value]);
        if (!value.includes("/")) throw new Error("Not a CIDR network");
        networks.push(value);
      } catch {
        problems.push("Unsupported Nessus target expression.");
      }
    }
  }
  return { exact, networks, problems };
}

export function compareApprovedScannerTargets(
  nessusRoutes: readonly Route[] | null,
  vulnersRoutes: readonly Route[] | null,
): ApprovedTargetParity {
  const result: ApprovedTargetParity = {
    mode: "approved-scopes-only",
    executedScanParityVerified: false,
    nessusRoutesAvailable: nessusRoutes !== null,
    vulnersRoutesAvailable: vulnersRoutes !== null,
    companies: [],
    matchedApprovedScopeCount: 0,
    unresolvedCompanyCount: 0,
  };
  // Disabled reviewed-routing is NOT evidence that no assets need scanning.
  if (nessusRoutes === null || vulnersRoutes === null) {
    result.unresolvedCompanyCount = 1; // global unverified state
    return result;
  }
  const customers = new Set([...nessusRoutes.map(r => r.companyId), ...vulnersRoutes.map(r => r.companyId)]);
  for (const companyId of [...customers].sort()) {
    const nRoutes = nessusRoutes.filter(r => r.companyId === companyId && r.provider === "nessus");
    const vRoutes = vulnersRoutes.filter(r => r.companyId === companyId && r.provider === "vulners");
    const problems: string[] = [];
    if (nRoutes.length !== 1) problems.push("Requires exactly one reviewed Nessus customer folder.");
    if (vRoutes.length !== 1) problems.push("Requires exactly one reviewed Vulners customer route.");
    const n = nRoutes.length === 1 ? normalized(nRoutes[0].targets, true) : normalized([], true);
    const v = vRoutes.length === 1 ? normalized(vRoutes[0].targets, false) : normalized([], false);
    problems.push(...n.problems, ...v.problems);
    const missing = [...n.exact].filter(([key]) => !v.exact.has(key)).map(([,value]) => value).sort();
    // A Vulners target under a Nessus CIDR might be intentional, but it
    // cannot establish equality of the range; never mark those as a match.
    const notExact = [...v.exact].filter(([key]) => !n.exact.has(key)).map(([,value]) => value).sort();
    const matchingExactCount = [...n.exact.keys()].filter(key => v.exact.has(key)).length;
    const status: ScopeStatus = problems.length || n.networks.length ? "unverifiable"
      : missing.length || notExact.length ? "approved-targets-differ" : "approved-targets-match";
    result.companies.push({
      companyId, status,
      nessusFolderId: nRoutes.length === 1 ? nRoutes[0].sourceScope ?? null : null,
      nessusExactCount: n.exact.size,
      vulnersExactCount: v.exact.size,
      matchingExactCount,
      missingFromVulners: missing,
      notExactNessusTargets: notExact,
      nessusNetworksRequiringExpansionReview: n.networks.sort(),
      problems,
    });
    if (status === "approved-targets-match") result.matchedApprovedScopeCount++;
    else result.unresolvedCompanyCount++;
  }
  return result;
}
