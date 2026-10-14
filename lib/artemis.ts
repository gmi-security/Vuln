import http from "node:http";
import https from "node:https";
import type { Severity } from "@/lib/types";
import { scannerExactTargetKey } from "./scanner-target-scope";

// Artemis (CERT Polska) adapter.
//
// Artemis is a modular attack-surface scanner with a REST API (routes under
// /api, auth via the "X-Api-Token" header — its FastAPI param is x_api_token):
//
//   GET  /api/analyses                     -> [{ id, target, tag, num_pending_tasks }, ...]
//   GET  /api/task-results?only_interesting=true&page=&page_size=&analysis_id=&search=
//                                          -> [ task-result objects ]
//   POST /api/add   { targets, tag, ... }  -> { ok, ids }
//
// Configure with:
//   ARTEMIS_API_URL    base URL, e.g. http://<host>:5000
//   ARTEMIS_API_TOKEN  value of the server's API_TOKEN
//
// Task-result field names vary by Artemis version; extractors below read
// several likely locations and fall back gracefully so a schema drift yields a
// weaker finding rather than a crash.

export type ArtemisConfig = { url: string; token: string };

export function artemisConfig(): ArtemisConfig | null {
  const url = process.env.ARTEMIS_API_URL;
  const token = process.env.ARTEMIS_API_TOKEN;
  if (!url || !token) return null;
  return { url: url.replace(/\/+$/, ""), token };
}

function request(
  config: ArtemisConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(config.url + path);
    const transport = target.protocol === "http:" ? http : https;
    const payload = body ? JSON.stringify(body) : null;
    const req = transport.request(
      {
        method,
        hostname: target.hostname,
        port: target.port || (target.protocol === "http:" ? 80 : 443),
        path: target.pathname + target.search,
        timeout: 25_000,
        headers: {
          Accept: "application/json",
          "X-Api-Token": config.token,
          ...(payload
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(payload),
              }
            : {}),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: data }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("Artemis request timed out")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function getJson(config: ArtemisConfig, path: string): Promise<any> {
  const res = await request(config, "GET", path);
  if (res.status === 401) {
    throw new Error("Artemis rejected the API token (401). Check ARTEMIS_API_TOKEN.");
  }
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Artemis GET ${path} failed: HTTP ${res.status}`);
  }
  try {
    return JSON.parse(res.text);
  } catch {
    throw new Error(
      `Artemis GET ${path} returned non-JSON — check that ARTEMIS_API_URL points at the Artemis API.`,
    );
  }
}

export async function artemisStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  ready: boolean;
  status: string;
  message: string;
  analysisCount: number;
}> {
  const config = artemisConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      ready: false,
      status: "not-configured",
      message: "ARTEMIS_API_URL / ARTEMIS_API_TOKEN not set",
      analysisCount: 0,
    };
  }
  try {
    const analyses = await getJson(config, "/api/analyses");
    if (!Array.isArray(analyses)) throw new Error("Artemis returned an invalid analysis list.");
    const n = analyses.length;
    return {
      configured: true,
      reachable: true,
      ready: true,
      status: "ready",
      message: `Reachable — ${n} analysis target(s)`,
      analysisCount: n,
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      ready: false,
      status: "unreachable",
      message: err instanceof Error ? err.message : "unreachable",
      analysisCount: 0,
    };
  }
}

// Queue new scanning tasks for a set of targets under a tag (POST /api/add).
export async function artemisAddTargets(
  targets: string[],
  tag: string,
  scope?: { config: ArtemisConfig; tag: string; targets: string[] },
): Promise<{ ok: boolean; ids: unknown[] }> {
  const config = scope?.config ?? artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  if (scope && (tag !== scope.tag || !targets.length || targets.some(target => !scope.targets.map(scannerExactTargetKey).includes(scannerExactTargetKey(target)))))
    throw new Error("Artemis launch exceeds its reviewed tag or targets.");
  if (targets.length === 0) return { ok: true, ids: [] };
  const res = await request(config, "POST", "/api/add", { targets, tag });
  if (res.status === 401) {
    throw new Error("Artemis rejected the API token (401). Check ARTEMIS_API_TOKEN.");
  }
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Artemis POST /api/add failed: HTTP ${res.status}`);
  }
  let json: any = {};
  try {
    json = JSON.parse(res.text);
  } catch {
    json = {};
  }
  if (scope && (json?.ok !== true || !Array.isArray(json.ids) || json.ids.length !== targets.length ||
      json.ids.some((id: unknown) => typeof id !== "string" || !id) || new Set(json.ids).size !== json.ids.length))
    throw new Error("Artemis did not confirm the requested target launches; inspect the scanner before retrying.");
  return { ok: json?.ok !== false, ids: json?.ids ?? [] };
}

export type ArtemisAnalysis = {
  id: string;
  target: string;
  tag: string;
  pending: number;
  stopped?: boolean;
};

export async function artemisListAnalyses(pinned?: ArtemisConfig, tag?: string): Promise<ArtemisAnalysis[]> {
  const config = pinned ?? artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  const rows = await getJson(config, tag === undefined ? "/api/analyses" : `/api/analyses?tag=${encodeURIComponent(tag)}`);
  if (!Array.isArray(rows)) throw new Error("Artemis returned an invalid analysis list.");
  if (pinned && (rows.length > 1000 || rows.some((r: any) => !r || typeof r.id !== "string" || !r.id ||
      typeof r.target !== "string" || !r.target || r.tag !== tag || typeof r.stopped !== "boolean" ||
      !Number.isSafeInteger(r.num_pending_tasks) || r.num_pending_tasks < 0) || new Set(rows.map((r: any) => r.id)).size !== rows.length))
    throw new Error("Artemis returned invalid or out-of-scope analysis identities.");
  return rows.map((r: any) => ({
    id: String(r?.id ?? r?._id ?? ""),
    target: String(r?.target ?? r?.target_string ?? r?.payload?.data ?? ""),
    tag: String(r?.tag ?? r?.payload_persistent?.tag ?? ""),
    pending: Number(r?.num_pending_tasks ?? 0),
    ...(pinned ? { stopped: r.stopped } : {}),
  }));
}

// Fetch a page of interesting task results (raw, for mapping / diagnostics).
export async function artemisTaskResults(
  pageSize = 200,
  page = 1,
  analysisId?: string,
  pinned?: ArtemisConfig,
): Promise<any[]> {
  const config = pinned ?? artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  const params = new URLSearchParams({
    only_interesting: "true",
    page: String(page),
    page_size: String(pageSize),
  });
  if (analysisId) params.set("analysis_id", analysisId);
  const data = await getJson(config, `/api/task-results?${params.toString()}`);
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.data)) return data.data;
  throw new Error("Artemis returned an invalid task result page.");
}

// ---- field extractors (defensive against version drift) -------------------

function pick(obj: any, ...paths: string[]): string {
  for (const p of paths) {
    const val = p.split(".").reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
    if (val != null && String(val).trim() !== "") return String(val);
  }
  return "";
}

const CRITICAL_HINTS = [
  "remote code execution",
  "rce",
  "sql injection",
  "sqli",
  "default credentials",
  "default password",
  "unauthenticated",
  "exposed database",
  "command injection",
];
const HIGH_HINTS = [
  "exposed",
  "disclosure",
  "vulnerable",
  "cve-",
  "admin panel",
  "directory listing",
  "backup",
  "config file",
  "misconfiguration",
  "takeover",
];

// Raw Artemis task results carry no severity field — it lives in the reporter
// layer. Derive a baseline from the module (`receiver`) that produced the
// result, then let explicit text or hint keywords raise (never lower) it.
const MODULE_SEVERITY: Record<string, Severity> = {
  sql_injection_detector: "Critical",
  lfi_detector: "High",
  nuclei: "High",
  shodan_vulns: "High",
  ftp_bruter: "High",
  mysql_bruter: "High",
  ssh_bruter: "High",
  postgresql_bruter: "High",
  wordpress_bruter: "High",
  bruter: "High",
  admin_panel_login_bruter: "High",
  ssh_bad_keys: "High",
  dangling_dns_detector: "High",
  "dangling-dns-detector": "High",
  wp_scanner: "High",
  wordpress_plugins: "Medium",
  joomla_scanner: "Medium",
  joomla_extensions: "Medium",
  drupal_scanner: "Medium",
  api_scanner: "Medium",
  removed_domain_existing_vhost: "Medium",
  directory_index: "Low",
  robots: "Info",
  port_scanner: "Low",
  domain_expiration_scanner: "Low",
  dns_scanner: "Info",
  mail_dns_scanner: "Low",
  device_identifier: "Info",
  ip_lookup: "Info",
  classifier: "Info",
};

const SEV_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0,
};

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

function inferSeverity(explicit: string, headline: string, receiver: string): Severity {
  const e = explicit.toLowerCase();
  if (e.includes("critical")) return "Critical";
  if (e.includes("high")) return "High";
  if (e.includes("medium")) return "Medium";
  if (e.includes("low")) return "Low";
  const base = MODULE_SEVERITY[receiver.toLowerCase()] ?? "Medium";
  const h = headline.toLowerCase();
  let textSev: Severity = "Info";
  if (CRITICAL_HINTS.some((k) => h.includes(k))) textSev = "Critical";
  else if (HIGH_HINTS.some((k) => h.includes(k))) textSev = "High";
  return maxSeverity(base, textSev);
}

const SEV_CVSS: Record<Severity, number> = {
  Critical: 9.5,
  High: 8.0,
  Medium: 5.5,
  Low: 3.0,
  Info: 0,
};

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

export type ArtemisFinding = {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  asset: string;
  tag: string;
  category: string;
  description: string;
};

export function mapArtemisResult(r: any): ArtemisFinding {
  const target = pick(
    r,
    "target_string",
    "target",
    "task.payload.host",
    "task.target_string",
    "task.payload.url",
  ) || "unknown";
  const headline =
    pick(r, "headline", "status_reason", "task.headline", "message", "name") ||
    "Artemis finding";
  const explicit = pick(r, "severity", "result.severity", "task.severity");
  const tag = pick(r, "tag", "task.payload_persistent.tag", "task.payload.tag").trim();
  const receiver =
    pick(r, "receiver", "task.headers.receiver", "task.type", "result.type") || "artemis";
  const severity = inferSeverity(explicit, headline, receiver);
  const cveMatch = headline.match(CVE_RE);
  return {
    cve: cveMatch ? cveMatch[0].toUpperCase() : `ARTEMIS-${receiver}`.toUpperCase(),
    title: headline.slice(0, 200),
    severity,
    cvss: SEV_CVSS[severity],
    asset: target,
    tag,
    category: `Artemis: ${receiver}`,
    description:
      pick(r, "status_reason", "message") ||
      JSON.stringify(r?.result ?? {}).slice(0, 600),
  };
}

// Pull all interesting task results (paginated) and map to findings.
export async function artemisImportFindings(scope?: { config: ArtemisConfig; tag: string; targets: string[] }): Promise<ArtemisFinding[]> {
  const config = scope?.config ?? artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  if (scope) return (await artemisCollectReviewedFindings(scope)).findings;
  const findings: ArtemisFinding[] = [];
  const pageSize = 200;
  for (let page = 1; page <= 25; page += 1) {
    const batch = await artemisTaskResults(pageSize, page);
    if (batch.length === 0) break;
    for (const r of batch) findings.push(mapArtemisResult(r));
    if (batch.length < pageSize) break;
    if (page === 25) throw new Error("Artemis findings exceeded the pagination limit; no complete result was returned.");
  }
  return findings;
}

export async function artemisCollectReviewedFindings(scope: { config: ArtemisConfig; tag: string; targets: string[] }): Promise<{ findings: ArtemisFinding[]; incompleteAnalyses: number }> {
  const allowed = new Set(scope.targets.map(scannerExactTargetKey));
  const roster = await artemisListAnalyses(scope.config, scope.tag);
  if (roster.some(row => !allowed.has(scannerExactTargetKey(row.target))))
    throw new Error("Artemis tag contains targets outside the reviewed customer scope.");
  const complete = roster.filter(row => row.pending === 0 && !row.stopped);
  const findings: ArtemisFinding[] = [], seen = new Set<string>();
  for (const analysis of complete) {
    for (let page = 1; page <= 25; page++) {
      const rows = await artemisTaskResults(200, page, analysis.id, scope.config);
      if (rows.length > 200) throw new Error("Artemis returned an oversized task result page.");
      for (const row of rows) {
        if (!row || typeof row.id !== "string" || !row.id || seen.has(row.id) || row.analysis_id !== analysis.id || row.tag !== scope.tag)
          throw new Error("Artemis returned duplicate or out-of-scope task results.");
        seen.add(row.id);
        if (seen.size > 5000) throw new Error("Artemis findings exceeded the customer collection limit.");
        findings.push(mapArtemisResult(row));
      }
      if (rows.length < 200) break;
      if (page === 25) throw new Error("Artemis findings exceeded the pagination limit; no complete result was returned.");
    }
  }
  const current = await artemisListAnalyses(scope.config, scope.tag);
  if (complete.some(before => !current.some(after => after.id === before.id && after.target === before.target &&
      after.tag === before.tag && after.pending === 0 && !after.stopped)))
    throw new Error("Artemis analysis changed during collection; results were withheld.");
  return { findings, incompleteAnalyses: roster.length - complete.length };
}
