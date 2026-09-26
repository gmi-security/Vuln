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
  risk: number; exprt: string; cvss: number | null; kev: boolean | null; exploit: number | null;
  exploitability: number | null; epss: number | null;
};
type Json = Record<string, any>;
const string = (value: unknown): string => typeof value === "string" ? value : "";
const number = (value: unknown): number => value === null || value === undefined || value === "" || typeof value === "boolean" ? -1 : Number.isFinite(Number(value)) ? Number(value) : -1;

// Version 1 mirrors the priority rules supplied for the Elastic tiles. It is a
// GMI policy, not CrowdStrike's own prioritization classification. EPSS (FIRST.org's
// exploit-prediction score, 0-1) is optional here: it is unknown at parse time
// (it requires a separate batched lookup) and applied in a second pass once
// fetched, via vulnerabilityRiskFromFields — see applyEpss.
export function vulnerabilityRiskFromFields(severity: string, exprt: string, cvss: number, kev: boolean, exploit: number, exploitability: number, epss?: number | null): { priority: string; risk: number } {
  const rank = (label: string) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[label] ?? 0);
  const sr = rank(severity), er = rank(exprt), x = exploitability;
  const e = exploit;
  const epssBoost = typeof epss === "number" ? Math.min(Math.max(epss, 0), 1) * 15 : 0;
  const risk = Math.round(((e >= 90 ? 30 : e >= 60 ? 22 : e >= 30 ? 10 : 0) + (kev ? 20 : 0) +
    (er === 4 ? 20 : er === 3 ? 15 : er === 2 ? 7 : er === 1 ? 2 : 0) +
    Math.min(Math.max(cvss, 0), 10) * 1.5 + Math.min(Math.max(x, 0), 4) * 2.5 + epssBoost +
    (sr === 4 ? 5 : sr === 3 ? 3 : sr === 2 ? 1 : 0)) * 10) / 10;
  const priority = e >= 90 || kev ? "P1 Exploited / KEV"
    : er === 4 || sr === 4 || cvss >= 9 || (e >= 60 && (sr >= 3 || cvss >= 7)) || risk >= 65 ? "P2 Critical risk"
    : er === 3 || sr === 3 || cvss >= 7 || (e >= 30 && x >= 3) || (typeof epss === "number" && epss >= 0.3 && (sr >= 3 || cvss >= 7)) || risk >= 40 ? "P3 High risk" : "Other";
  return { priority, risk };
}
export function vulnerabilityRisk(cve: Json, epss?: number | null): { priority: string; risk: number } {
  return vulnerabilityRiskFromFields(string(cve.severity).toUpperCase(), string(cve.exprt_rating).toUpperCase(), number(cve.base_score),
    cve.cisa_info?.is_cisa_kev === true || cve.is_cisa_kev === true, number(cve.exploit_status), number(cve.exploitability_score), epss);
}
export function vulnerabilityPriority(cve: Json): string { return vulnerabilityRisk(cve).priority; }

export function normalizeVulnerability(raw: Json): Vulnerability {
  if (!raw || typeof raw !== "object" || !string(raw.id)) throw new DashboardError("CrowdStrike returned a finding without its stable ID. No totals were saved.");
  const cve = raw.cve ?? {};
  const assessment = vulnerabilityRisk(cve), cvss = number(cve.base_score), exploit = number(cve.exploit_status), exploitability = number(cve.exploitability_score);
  const kev = cve.cisa_info?.is_cisa_kev ?? cve.is_cisa_kev;
  return { id: raw.id, cid: string(raw.cid), hostId: string(raw.aid), hostname: string(raw.host_info?.hostname),
    cve: string(cve.id), severity: string(cve.severity).toUpperCase() || "UNKNOWN",
    status: string(raw.status).toLowerCase() || "unknown", ...assessment, updated: string(raw.updated_timestamp),
    exprt: string(cve.exprt_rating).toUpperCase() || "UNKNOWN", cvss: cvss >= 0 ? cvss : null,
    kev: typeof kev === "boolean" ? kev : null, exploit: exploit >= 0 ? exploit : null,
    exploitability: exploitability >= 0 ? exploitability : null, epss: null };
}

// Applied once EPSS scores are fetched for the distinct CVEs in a collected
// batch (network I/O lives in crowdstrike-dashboard-client.ts). Re-derives
// risk/priority with the same formula normalizeVulnerability used, now with
// EPSS folded in, so the score a finding ends with is identical whether or
// not EPSS happened to already be known at parse time.
export function applyEpss(records: Iterable<Vulnerability>, epss: Map<string, number>): void {
  for (const row of records) {
    const score = epss.get(row.cve.toUpperCase());
    if (score === undefined) continue;
    row.epss = score;
    Object.assign(row, vulnerabilityRiskFromFields(row.severity, row.exprt, row.cvss ?? -1, row.kev === true, row.exploit ?? -1, row.exploitability ?? -1, score));
  }
}

export function patchWorklist(records: Iterable<Vulnerability>, top: number): QueryResult {
  const eligible = [...records].filter((row) => ["open", "reopen"].includes(row.status) && row.priority !== "Other");
  const hosts = new Map<string, Set<string>>();
  for (const row of eligible) {
    if (!row.hostId) throw new DashboardError("A finding is missing its host ID. The patch worklist cannot reliably identify its device.");
    if (row.cve) {
      const members = hosts.get(row.cve) ?? new Set<string>();
      members.add(JSON.stringify([row.cid, row.hostId])); hosts.set(row.cve, members);
    }
  }
  eligible.sort((a, b) => a.priority.localeCompare(b.priority) || b.risk - a.risk ||
    (hosts.get(b.cve)?.size ?? 0) - (hosts.get(a.cve)?.size ?? 0) || a.cve.localeCompare(b.cve) || a.cid.localeCompare(b.cid) || a.id.localeCompare(b.id));
  const names = ["priority", "risk_score", "cve", "device", "affected_devices_for_cve", "severity", "exprt", "cvss", "cisa_kev", "epss", "exploit_status", "status", "source_updated_at", "host_id", "tenant_id", "finding_id"];
  return {
    columns: names.map((name) => ({ name, type: ["risk_score", "cvss", "epss"].includes(name) ? "double"
      : ["affected_devices_for_cve", "exploit_status"].includes(name) ? "long" : name === "cisa_kev" ? "boolean" : name === "source_updated_at" ? "date" : "keyword" })),
    rows: eligible.slice(0, top).map((row) => [row.priority, row.risk, row.cve || null, row.hostname.slice(0, 2000) || "Unknown host",
      hosts.get(row.cve)?.size ?? null, row.severity, row.exprt, row.cvss, row.kev, row.epss, row.exploit, row.status,
      row.updated || null, row.hostId, row.cid || null, row.id]),
    truncated: false,
    note: `Top ${Math.min(top, eligible.length)} of ${eligible.length} open P1–P3 findings in this filter. Ordered by GMI priority, risk score, then affected devices. Device counts cover the matching P1–P3 population. EPSS is FIRST.org's probability of exploitation in the next 30 days (0-1); blank means it was not returned. One row is a finding on a device; a patch may resolve multiple findings. Use the CVE and finding ID to check remediation in Falcon.`,
  };
}

export function summarizeVulnerabilities(records: Iterable<Vulnerability>, options: CrowdStrikeOptions): QueryResult {
  if (options.view === "cve-devices") return cveDeviceTable(records, options.top);
  if (options.view === "patch-worklist") return patchWorklist(records, options.top);
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

export function cveDeviceTable(records: Iterable<Vulnerability>, top: number): QueryResult {
  const rank = (severity: string) => ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1 }[severity] ?? 0);
  const groups = new Map<string, { severity: string; devices: Set<string>; findings: Set<string>; cvss: number | null; kev: boolean | null; epss: number | null }>();
  let excluded = 0;
  for (const row of records) {
    if (!["open", "reopen"].includes(row.status)) continue;
    if (!/^CVE-\d{4}-\d+$/i.test(row.cve)) { excluded++; continue; }
    if (!row.hostId) throw new DashboardError("A CVE finding is missing its host ID. Complete affected-device counts cannot be calculated.");
    const cve = row.cve.toUpperCase();
    const group = groups.get(cve) ?? { severity: row.severity, devices: new Set<string>(), findings: new Set<string>(), cvss: null, kev: null, epss: null };
    group.devices.add(JSON.stringify([row.cid, row.hostId]));
    group.findings.add(JSON.stringify([row.cid, row.id]));
    if (rank(row.severity) > rank(group.severity)) group.severity = row.severity;
    if (row.cvss !== null) group.cvss = Math.max(group.cvss ?? 0, row.cvss);
    if (row.kev !== null) group.kev = group.kev === true || row.kev;
    if (row.epss !== null) group.epss = row.epss;
    groups.set(cve, group);
  }
  const rows = [...groups].sort(([a, x], [b, y]) => rank(y.severity) - rank(x.severity) || y.devices.size - x.devices.size || a.localeCompare(b));
  return { columns: [{ name: "cve", type: "keyword" }, { name: "severity", type: "keyword" },
    { name: "affected_devices", type: "long" }, { name: "open_findings", type: "long" },
    { name: "cvss", type: "double" }, { name: "cisa_kev", type: "boolean" }, { name: "epss", type: "double" }],
    rows: rows.slice(0, top).map(([cve, row]) => [cve, row.severity, row.devices.size, row.findings.size, row.cvss, row.kev, row.epss]), truncated: false,
    note: `Top ${Math.min(top, rows.length)} CVEs by severity, then unique affected devices. Critical, High, Medium, Low, None, Unknown. Open/reopened findings only; each tenant/device counts once per CVE. EPSS is FIRST.org's probability of exploitation in the next 30 days (0-1); blank means it was not returned. ${excluded ? `${excluded} findings without a CVE identifier excluded. ` : ""}Counts reflect the matching population observed during collection.` };
}

// Dataset adapters own endpoint-specific pagination and normalization. Future
// Hosts/Discover datasets can implement the same interface without tile routes.
export const CROWDSTRIKE_DATASETS = {
  vulnerabilities: { path: "/spotlight/combined/vulnerabilities/v1", facets: ["cve", "host_info"], normalize: normalizeVulnerability, summarize: summarizeVulnerabilities },
};
