import { DashboardError, type CrowdStrikeOptions, type QueryResult } from "./elastic-dashboard";

export const FALCON_REGIONS = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
} as const;
export type FalconRegion = keyof typeof FALCON_REGIONS;
export type CrowdStrikeConnection = { region: FalconRegion; clientId: string; clientSecret: string };
export type Vulnerability = {
  id: string; cid: string; hostId: string; hostname: string; cve: string; severity: string;
  status: string; priority: string; updated: string;
};
type Json = Record<string, any>;
const string = (value: unknown): string => typeof value === "string" ? value : "";
const number = (value: unknown): number => value === null || value === undefined || value === "" || typeof value === "boolean" ? -1 : Number.isFinite(Number(value)) ? Number(value) : -1;

// Version 1 mirrors the priority rules supplied for the Elastic tiles. It is a
// GMI policy, not CrowdStrike's own prioritization classification.
export function vulnerabilityPriority(cve: Json): string {
  const severity = string(cve.severity).toUpperCase();
  const exprt = string(cve.exprt_rating).toUpperCase();
  const rank = (label: string) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[label] ?? 0);
  const e = number(cve.exploit_status), cvss = number(cve.base_score), x = number(cve.exploitability_score);
  const kev = cve.cisa_info?.is_cisa_kev === true || cve.is_cisa_kev === true;
  const sr = rank(severity), er = rank(exprt);
  const risk = Math.round(((e >= 90 ? 30 : e >= 60 ? 22 : e >= 30 ? 10 : 0) + (kev ? 20 : 0) +
    (er === 4 ? 20 : er === 3 ? 15 : er === 2 ? 7 : er === 1 ? 2 : 0) +
    Math.min(Math.max(cvss, 0), 10) * 1.5 + Math.min(Math.max(x, 0), 4) * 2.5 +
    (sr === 4 ? 5 : sr === 3 ? 3 : sr === 2 ? 1 : 0)) * 10) / 10;
  if (e >= 90 || kev) return "P1 Exploited / KEV";
  if (er === 4 || sr === 4 || cvss >= 9 || (e >= 60 && (sr >= 3 || cvss >= 7)) || risk >= 65) return "P2 Critical risk";
  if (er === 3 || sr === 3 || cvss >= 7 || (e >= 30 && x >= 3) || risk >= 40) return "P3 High risk";
  return "Other";
}

export function normalizeVulnerability(raw: Json): Vulnerability {
  if (!raw || typeof raw !== "object" || !string(raw.id)) throw new DashboardError("CrowdStrike returned a finding without its stable ID. No totals were saved.");
  const cve = raw.cve ?? {};
  return { id: raw.id, cid: string(raw.cid), hostId: string(raw.aid), hostname: string(raw.host_info?.hostname),
    cve: string(cve.id), severity: string(cve.severity).toUpperCase() || "UNKNOWN",
    status: string(raw.status).toLowerCase() || "unknown", priority: vulnerabilityPriority(cve), updated: string(raw.updated_timestamp) };
}

export function summarizeVulnerabilities(records: Iterable<Vulnerability>, options: CrowdStrikeOptions): QueryResult {
  const groups = new Map<string, Set<string>>();
  const overall = new Set<string>();
  for (const row of records) {
    if ((options.measure === "hosts" || options.groupBy === "host") && !row.hostId) throw new DashboardError("A finding is missing its host ID. A complete host count cannot be calculated.");
    if ((options.measure === "cves" || options.groupBy === "cve") && !row.cve) throw new DashboardError("A finding is missing its CVE ID. Narrow the filter to CVE findings before counting CVEs.");
    const identity = options.measure === "cves" ? row.cve : JSON.stringify([row.cid, options.measure === "hosts" ? row.hostId : row.id]);
    overall.add(identity);
    const group = options.groupBy === "host" ? `${row.hostname || "Unknown host"} (${row.cid ? row.cid + "/" : ""}${row.hostId})`
      : options.groupBy === "cve" ? row.cve : options.groupBy === "none" ? "total" : row[options.groupBy];
    const members = groups.get(group) ?? new Set<string>();
    members.add(identity); groups.set(group, members);
  }
  if (options.groupBy === "none") return { columns: [{ name: options.measure, type: "long" }], rows: [[overall.size]], truncated: false };
  const rows = [...groups].map(([key, values]) => [key, values.size] as [string, number])
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return { columns: [{ name: options.groupBy, type: "keyword" }, { name: options.measure, type: "long" }],
    rows: rows.slice(0, options.top), truncated: false,
    note: `Top ${Math.min(rows.length, options.top)} of ${rows.length} groups, calculated from all matching findings. Unique CVEs or hosts can appear in more than one group.` };
}

// Dataset adapters own endpoint-specific pagination and normalization. Future
// Hosts/Discover datasets can implement the same interface without tile routes.
export const CROWDSTRIKE_DATASETS = {
  vulnerabilities: { path: "/spotlight/combined/vulnerabilities/v1", facets: "cve,host_info", normalize: normalizeVulnerability, summarize: summarizeVulnerabilities },
};
