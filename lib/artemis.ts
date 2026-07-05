import http from "node:http";
import https from "node:https";
import type { Severity } from "@/lib/types";

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
//   ARTEMIS_API_URL    base URL, e.g. http://137.184.89.60:5000
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
    const n = Array.isArray(analyses) ? analyses.length : 0;
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

export type ArtemisAnalysis = {
  id: string;
  target: string;
  tag: string;
  pending: number;
};

export async function artemisListAnalyses(): Promise<ArtemisAnalysis[]> {
  const config = artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  const rows = await getJson(config, "/api/analyses");
  if (!Array.isArray(rows)) return [];
  return rows.map((r: any) => ({
    id: String(r?.id ?? r?._id ?? ""),
    target: String(r?.target ?? r?.target_string ?? r?.payload?.data ?? ""),
    tag: String(r?.tag ?? r?.payload_persistent?.tag ?? ""),
    pending: Number(r?.num_pending_tasks ?? 0),
  }));
}

// Fetch a page of interesting task results (raw, for mapping / diagnostics).
export async function artemisTaskResults(
  pageSize = 200,
  page = 1,
  analysisId?: string,
): Promise<any[]> {
  const config = artemisConfig();
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
  return [];
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

function inferSeverity(explicit: string, headline: string): Severity {
  const e = explicit.toLowerCase();
  if (e.includes("critical")) return "Critical";
  if (e.includes("high")) return "High";
  if (e.includes("medium")) return "Medium";
  if (e.includes("low")) return "Low";
  const h = headline.toLowerCase();
  if (CRITICAL_HINTS.some((k) => h.includes(k))) return "Critical";
  if (HIGH_HINTS.some((k) => h.includes(k))) return "High";
  return "Medium"; // Artemis only surfaces "interesting" results here
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
  const tag = pick(r, "tag", "task.payload_persistent.tag", "task.payload.tag");
  const kind = pick(r, "task.type", "task.headers.receiver", "result.type") || "artemis";
  const severity = inferSeverity(explicit, headline);
  const cveMatch = headline.match(CVE_RE);
  return {
    cve: cveMatch ? cveMatch[0].toUpperCase() : `ARTEMIS-${kind}`.toUpperCase(),
    title: headline.slice(0, 200),
    severity,
    cvss: SEV_CVSS[severity],
    asset: target,
    tag,
    category: `Artemis: ${kind}`,
    description:
      pick(r, "status_reason", "message") ||
      JSON.stringify(r?.result ?? {}).slice(0, 600),
  };
}

// Pull all interesting task results (paginated) and map to findings.
export async function artemisImportFindings(): Promise<ArtemisFinding[]> {
  const config = artemisConfig();
  if (!config) throw new Error("Artemis is not configured.");
  const findings: ArtemisFinding[] = [];
  const pageSize = 200;
  for (let page = 1; page <= 25; page += 1) {
    const batch = await artemisTaskResults(pageSize, page);
    if (batch.length === 0) break;
    for (const r of batch) findings.push(mapArtemisResult(r));
    if (batch.length < pageSize) break;
  }
  return findings;
}
