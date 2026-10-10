import http from "node:http";
import https from "node:https";
import type { Severity } from "@/lib/types";
import { scannerExactTargetKey } from "./scanner-target-scope";

// SpiderFoot (open-source) adapter.
//
// The OSS SpiderFoot server exposes the same HTTP endpoints its own web UI
// calls — there is no separate "REST API license" and, by default, no auth:
//
//   POST /startscan            scanname, scantarget, usecase|modulelist|typelist
//                              -> JSON ["SUCCESS", scanId]
//   GET  /scanlist             -> [[id, name, target, created, started, finished,
//                                   status, resultCount, riskMatrix], ...]
//   GET  /scanstatus?id=       -> [name, target, created, started, ended, status, ...]
//   GET  /scanexportjsonmulti?ids=id1,id2
//                              -> [{ data, event_type, module, source_data,
//                                    false_positive, last_seen, scan_name,
//                                    scan_target }, ...]
//
// Configure with:
//   SPIDERFOOT_URL             base URL, e.g. http://<host>:5000
//   SPIDERFOOT_USER / _PASS    optional HTTP Basic creds if the instance is
//                              fronted by auth
//
// NOTE: if SPIDERFOOT_URL points at a custom orchestrator (not stock
// SpiderFoot) the endpoint paths may differ; getJson() throws cleanly on a
// non-JSON / non-2xx response rather than importing garbage.

export type SpiderfootConfig = { url: string; auth: string | null; insecure: boolean };

export function spiderfootConfig(): SpiderfootConfig | null {
  const url = process.env.SPIDERFOOT_URL;
  if (!url) return null;
  const user = process.env.SPIDERFOOT_USER;
  const pass = process.env.SPIDERFOOT_PASS;
  const auth = user && pass ? Buffer.from(`${user}:${pass}`).toString("base64") : null;
  return {
    url: url.replace(/\/+$/, ""),
    auth,
    // T-Pot (and many self-hosted SpiderFoot deployments) front the UI with a
    // self-signed cert; set SPIDERFOOT_TLS_INSECURE=1 to skip verification.
    insecure: process.env.SPIDERFOOT_TLS_INSECURE === "1",
  };
}

function request(
  config: SpiderfootConfig,
  method: string,
  path: string,
  form?: Record<string, string>,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(config.url + path);
    const transport = target.protocol === "http:" ? http : https;
    const body = form ? new URLSearchParams(form).toString() : null;
    const req = transport.request(
      {
        method,
        hostname: target.hostname,
        port: target.port || (target.protocol === "http:" ? 80 : 443),
        path: target.pathname + target.search,
        timeout: 20_000,
        ...(target.protocol === "https:" ? { rejectUnauthorized: !config.insecure } : {}),
        headers: {
          Accept: "application/json",
          ...(config.auth ? { Authorization: `Basic ${config.auth}` } : {}),
          ...(body
            ? {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": Buffer.byteLength(body),
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
    req.on("timeout", () => req.destroy(new Error("SpiderFoot request timed out")));
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function getJson(config: SpiderfootConfig, path: string): Promise<any> {
  const res = await request(config, "GET", path);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`SpiderFoot GET ${path} failed: HTTP ${res.status}`);
  }
  try {
    return JSON.parse(res.text);
  } catch {
    throw new Error(
      `SpiderFoot GET ${path} returned non-JSON — check that SPIDERFOOT_URL points at the SpiderFoot server API.`,
    );
  }
}

// Reachability / activation probe. Lists scans as a lightweight liveness check.
export async function spiderfootStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  ready: boolean;
  status: string;
  message: string;
  scanCount: number;
}> {
  const config = spiderfootConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      ready: false,
      status: "not-configured",
      message: "SPIDERFOOT_URL not set",
      scanCount: 0,
    };
  }
  try {
    const list = await getJson(config, "/scanlist");
    const n = Array.isArray(list) ? list.length : 0;
    return {
      configured: true,
      reachable: true,
      ready: true,
      status: "ready",
      message: `Reachable — ${n} scan(s) available`,
      scanCount: n,
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      ready: false,
      status: "unreachable",
      message: err instanceof Error ? err.message : "unreachable",
      scanCount: 0,
    };
  }
}

export type SpiderfootScan = {
  id: string;
  name: string;
  target: string;
  status: string;
  resultCount: number;
  risk: { HIGH?: number; MEDIUM?: number; LOW?: number; INFO?: number };
  finishedAt?: string;
};

export async function spiderfootListScans(pinned?: SpiderfootConfig): Promise<SpiderfootScan[]> {
  const config = pinned ?? spiderfootConfig();
  if (!config) throw new Error("SpiderFoot is not configured.");
  const rows = await getJson(config, "/scanlist");
  if (!Array.isArray(rows)) throw new Error("SpiderFoot returned an invalid scan roster.");
  if (pinned && (rows.some((r: any) => !Array.isArray(r) || typeof r[0] !== "string" || !/^[A-Za-z0-9_-]+$/.test(r[0]) ||
      typeof r[1] !== "string" || typeof r[2] !== "string" || !r[2] || typeof r[5] !== "string" ||
      typeof r[6] !== "string" || !Number.isSafeInteger(r[7]) || r[7] < 0) || new Set(rows.map((r: any) => r[0])).size !== rows.length))
    throw new Error("SpiderFoot returned invalid or duplicate scan identities.");
  return rows.map((r: any[]) => ({
    id: String(r[0]),
    name: String(r[1] ?? r[0]),
    target: String(r[2] ?? ""),
    status: String(r[6] ?? "UNKNOWN"),
    resultCount: Number(r[7] ?? 0),
    risk: r[8] && typeof r[8] === "object" ? r[8] : {},
    ...(pinned ? { finishedAt: r[5] } : {}),
  }));
}

// Launch a scan. usecase is one of SpiderFoot's built-in cases: "all",
// "Footprint", "Investigate", "Passive". Returns the new scan id.
export async function spiderfootStartScan(
  name: string,
  target: string,
  usecase = "all",
  scope?: { config: SpiderfootConfig; targets: string[] },
): Promise<string> {
  const config = scope?.config ?? spiderfootConfig();
  if (!config) throw new Error("SpiderFoot is not configured.");
  if (scope && !scope.targets.map(scannerExactTargetKey).includes(scannerExactTargetKey(target)))
    throw new Error("SpiderFoot launch target is outside the reviewed customer scope.");
  const res = await request(config, "POST", "/startscan", {
    scanname: name,
    scantarget: target,
    usecase,
    modulelist: "",
    typelist: "",
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`SpiderFoot startscan failed: HTTP ${res.status}`);
  }
  let parsed: any;
  try {
    parsed = JSON.parse(res.text);
  } catch {
    throw new Error("SpiderFoot startscan returned non-JSON.");
  }
  if (Array.isArray(parsed) && parsed[0] === "SUCCESS" && (!scope || typeof parsed[1] === "string" && /^[A-Za-z0-9_-]+$/.test(parsed[1]))) return String(parsed[1]);
  throw new Error(
    `SpiderFoot startscan error: ${Array.isArray(parsed) ? parsed[1] : res.text}`,
  );
}

// SpiderFoot event types that represent actual security exposure, mapped to a
// console severity. Pure-OSINT/informational event types (INTERNET_NAME,
// IP_ADDRESS, etc.) are intentionally excluded so the findings table stays
// signal, not noise.
const SF_VULN_SEVERITY: Record<string, Severity> = {
  VULNERABILITY_CVE_CRITICAL: "Critical",
  VULNERABILITY_CVE_HIGH: "High",
  VULNERABILITY_CVE_MEDIUM: "Medium",
  VULNERABILITY_CVE_LOW: "Low",
  VULNERABILITY_GENERAL: "Medium",
  VULNERABILITY_DISCLOSURE: "Medium",
  VULNERABILITY_THIRD_PARTY: "Medium",
};

const SF_EXPOSURE_SEVERITY: Record<string, Severity> = {
  EMAILADDR_COMPROMISED: "High",
  PASSWORD_COMPROMISED: "High",
  ACCOUNT_EXTERNAL_OWNED_COMPROMISED: "High",
  HASH_COMPROMISED: "Medium",
  DEFACED_INTERNET_NAME: "High",
  MALICIOUS_IPADDR: "High",
  MALICIOUS_INTERNET_NAME: "High",
  MALICIOUS_AFFILIATE_INTERNET_NAME: "Medium",
  MALICIOUS_SUBDOMAIN: "Medium",
  BLACKLISTED_IPADDR: "Medium",
  BLACKLISTED_INTERNET_NAME: "Medium",
  LEAKSITE_CONTENT: "Medium",
  LEAKSITE_URL: "Low",
  DARKNET_MENTION_URL: "Medium",
  TCP_PORT_OPEN: "Info",
  UDP_PORT_OPEN: "Info",
  WEBSERVER_TECHNOLOGY: "Info",
};

const SEV_CVSS: Record<Severity, number> = {
  Critical: 9.5,
  High: 8.0,
  Medium: 5.5,
  Low: 3.0,
  Info: 0,
};

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

// SpiderFoot's `source_data` is the DATA payload of the parent event in the
// discovery chain — for most event types that's a hostname/IP/URL, but for
// an event discovered off e.g. a WEBSERVER_HTTPHEADERS or RAW_RIR_DATA
// parent, it's the parent's raw data: a JSON header dump, a whois blob, etc.
// Using it unvalidated as the asset identifier puts that blob straight into
// the findings table and every page that lists assets by it.
export function isGarbageAssetIdentifier(id: string): boolean {
  const t = id.trim();
  if (!t) return true;
  if (t.length > 200) return true;
  if (t.startsWith("{") || t.startsWith("[")) return true;
  return false;
}

function humanizeEventType(t: string): string {
  return t
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export type SpiderfootFinding = {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  asset: string;
  category: string;
  description: string;
  module: string;
};

// Pull a finished scan's events and map the security-relevant ones to findings.
export async function spiderfootImportFindings(
  scanId: string,
  scope?: { config: SpiderfootConfig; targets: string[]; scan: SpiderfootScan },
): Promise<SpiderfootFinding[]> {
  const config = scope?.config ?? spiderfootConfig();
  if (!config) throw new Error("SpiderFoot is not configured.");
  const signature = (scan: SpiderfootScan) => JSON.stringify([scan.id, scan.name, scan.target, scan.status, scan.finishedAt, scan.resultCount]);
  const verify = async () => {
    if (!scope) return;
    if (scope.scan.id !== scanId || scope.scan.status !== "FINISHED" || !scope.scan.finishedAt || scope.scan.finishedAt === "Not yet" ||
        !scope.targets.map(scannerExactTargetKey).includes(scannerExactTargetKey(scope.scan.target)))
      throw new Error("SpiderFoot scan is not finished in its reviewed target scope.");
    const current = (await spiderfootListScans(config)).find(scan => scan.id === scanId);
    if (!current || signature(current) !== signature(scope.scan)) throw new Error("SpiderFoot scan changed during collection; results were withheld.");
  };
  await verify();
  const events = await getJson(
    config,
    `/scanexportjsonmulti?ids=${encodeURIComponent(scanId)}`,
  );
  if (!Array.isArray(events)) throw new Error("SpiderFoot returned an invalid scan event list.");
  if (scope && events.some((ev: any) => !ev || typeof ev !== "object" || typeof ev.scan_target !== "string" ||
      scannerExactTargetKey(ev.scan_target) !== scannerExactTargetKey(scope.scan.target) || ev.scan_name !== scope.scan.name))
    throw new Error("SpiderFoot returned an event outside the reviewed scan.");
  const out: SpiderfootFinding[] = [];
  for (const ev of events) {
    const type = String(ev.event_type ?? "");
    const severity = SF_VULN_SEVERITY[type] ?? SF_EXPOSURE_SEVERITY[type];
    if (!severity) continue; // skip informational OSINT events
    if (String(ev.false_positive ?? "0") === "1") continue;
    const data = String(ev.data ?? "").trim();
    const sourceData = String(ev.source_data ?? "").trim();
    const scanTarget = String(ev.scan_target ?? "").trim();
    const asset =
      (!isGarbageAssetIdentifier(sourceData) && sourceData) || scanTarget || "unknown";
    const cveMatch = data.match(CVE_RE) ?? asset.match(CVE_RE);
    const cve = cveMatch ? cveMatch[0].toUpperCase() : `SF-${type}`;
    const firstLine = data.split("\n")[0]?.slice(0, 120) ?? "";
    const title = `${humanizeEventType(type)}${firstLine ? ` — ${firstLine}` : ""}`;
    out.push({
      cve,
      title: title.slice(0, 200),
      severity,
      cvss: SEV_CVSS[severity],
      asset,
      category: `SpiderFoot: ${type}`,
      description: data || humanizeEventType(type),
      module: String(ev.module ?? ""),
    });
  }
  await verify();
  return out;
}
