import type { TopFix } from "./reporting-top-fixes";

export type RemediationFix = Omit<TopFix, "cve"> & {
  cves: string[]; reference?: string; grouping: "vendor-remediation" | "single-cve";
};
export type RemediationWorklist = { totalGroups: number; limit: number; rows: RemediationFix[]; notices?: string[] };
const rank: Record<string,number> = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0,NONE:0,UNKNOWN:-1};
export function compareRemediationFixes(a: Pick<RemediationFix,"severity"|"deviceCount"|"source"|"maxRisk"|"id">, b: typeof a): number {
  return (rank[b.severity.toUpperCase()] ?? -1)-(rank[a.severity.toUpperCase()] ?? -1) ||
    b.deviceCount-a.deviceCount || (a.source ?? "").localeCompare(b.source ?? "") ||
    b.maxRisk-a.maxRisk || a.id.localeCompare(b.id);
}
