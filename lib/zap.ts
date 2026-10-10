import { randomUUID } from "node:crypto";
import { scannerWebOrigin } from "./scanner-target-scope";
import type { Severity } from "@/lib/types";

// OWASP ZAP adapter — dynamic application security testing (DAST) against a
// live target URL (class: active scan, mirrors the Nmap/Vulners-Bridge
// active-scanning shape, but for web apps instead of hosts).
//
// ZAP sits behind a gateway that routes by Host header rather than by URL
// path, so every request needs BOTH the apikey query param AND a literal
// "Host: zap" header — neither alone is enough.
//
// Configure with:
//   ZAP_URL        base URL of the ZAP gateway
//   ZAP_API_KEY    ZAP API key

export type ZapConfig = { baseUrl: string; apiKey: string };

export function zapConfig(): ZapConfig | null {
  const baseUrl = process.env.ZAP_URL?.trim();
  const apiKey = process.env.ZAP_API_KEY?.trim();
  if (!baseUrl || !apiKey) return null;
  return { baseUrl: baseUrl.replace(/\/+$/, ""), apiKey };
}

// Node's fetch() throws a generic "fetch failed" TypeError for DNS/connect
// failures and buries the actual reason (ECONNREFUSED, ENOTFOUND, an abort
// timeout, ...) in `.cause`. Surface that instead so a health-check error
// says what actually went wrong rather than the useless top-level message.
function describeFetchError(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as { cause?: unknown }).cause;
    if (err.name === "AbortError" || err.name === "TimeoutError") {
      return "Request timed out.";
    }
    if (cause instanceof Error) return cause.message;
    if (typeof cause === "string") return cause;
    return err.message;
  }
  return "Connection failed.";
}

// Every ZAP call needs `Host: zap` (gateway routing) and `apikey` on the
// query string. action/status calls are cheap and bounded at 15s; the report
// pull can be large, so it gets its own longer timeout at the call site.
async function zapFetch(
  cfg: ZapConfig,
  path: string,
  params: Record<string, string> = {},
  timeoutMs = 15_000,
): Promise<any> {
  const qs = new URLSearchParams({ ...params, apikey: cfg.apiKey });
  const res = await fetch(`${cfg.baseUrl}${path}?${qs.toString()}`, {
    headers: { Host: "zap" },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    throw new Error(
      `ZAP ${path} HTTP ${res.status}: ${await res.text().catch(() => res.statusText)}`,
    );
  }
  return res.json();
}

// --- Reachability probe -----------------------------------------------------
// Uses /JSON/core/view/version/ — the cheapest read-only endpoint ZAP exposes,
// no scan state touched.
export async function zapStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const config = zapConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set ZAP_URL and ZAP_API_KEY.",
    };
  }
  try {
    const data = await zapFetch(config, "/JSON/core/view/version/");
    return {
      configured: true,
      reachable: Boolean(data?.version),
      status: data?.version ? "Connected" : "Unreachable",
      message: data?.version ? `ZAP ${data.version} reachable.` : "ZAP did not return a version.",
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: describeFetchError(err),
    };
  }
}

// --- Spider (crawl) ----------------------------------------------------------
export async function zapStartSpider(targetUrl: string, scope?: ZapScope): Promise<string> {
  const config = scope?.config ?? zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  if (scope && scannerWebOrigin(targetUrl, true) !== scope.origin) throw new Error("ZAP target is outside its approved origin.");
  const data = await zapFetch(config, "/JSON/spider/action/scan/", {
    url: targetUrl,
    ...(scope ? { contextName: scope.name, subtreeOnly: "true", recurse: "true" } : {}),
  });
  const scanId = data?.scan;
  if (!validZapId(scanId)) {
    throw new Error("ZAP spider scan: no scan id returned.");
  }
  return String(scanId);
}

export async function zapSpiderStatus(scanId: string, pinned?: ZapConfig): Promise<number> {
  const config = pinned ?? zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  if (!validZapId(scanId)) throw new Error("ZAP scan ID is invalid.");
  const data = await zapFetch(config, "/JSON/spider/view/status/", { scanId });
  const status = Number(data?.status);
  if (!/^(?:[0-9]|[1-9][0-9]|100)$/.test(String(data?.status)) || !Number.isInteger(status)) throw new Error("ZAP spider status: malformed response.");
  return status;
}

// --- Active scan --------------------------------------------------------------
export async function zapStartActiveScan(targetUrl: string, scope?: ZapScope): Promise<string> {
  const config = scope?.config ?? zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  if (scope && scannerWebOrigin(targetUrl, true) !== scope.origin) throw new Error("ZAP target is outside its approved origin.");
  const data = await zapFetch(config, "/JSON/ascan/action/scan/", {
    url: targetUrl,
    ...(scope ? { contextId: scope.id, recurse: "true", inScopeOnly: "true" } : {}),
  });
  const scanId = data?.scan;
  if (!validZapId(scanId)) {
    throw new Error("ZAP active scan: no scan id returned.");
  }
  return String(scanId);
}

export async function zapActiveScanStatus(scanId: string, pinned?: ZapConfig): Promise<number> {
  const config = pinned ?? zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  if (!validZapId(scanId)) throw new Error("ZAP scan ID is invalid.");
  const data = await zapFetch(config, "/JSON/ascan/view/status/", { scanId });
  const status = Number(data?.status);
  if (!/^(?:[0-9]|[1-9][0-9]|100)$/.test(String(data?.status)) || !Number.isInteger(status)) throw new Error("ZAP active scan status: malformed response.");
  return status;
}

// ZAP only has four risk levels — never emit Critical from this mapper.
export function zapMapRiskToSeverity(riskcode: unknown): Severity {
  switch (String(riskcode ?? "")) {
    case "3":
      return "High";
    case "2":
      return "Medium";
    case "1":
      return "Low";
    default:
      return "Info";
  }
}

function severityCvss(sev: Severity): number {
  return { Critical: 9.5, High: 8.0, Medium: 5.5, Low: 3.0, Info: 0 }[sev];
}

const CVE_RE = /CVE-\d{4}-\d{4,}/i;

// ZAP alerts are weakness classes (CWE), not CVEs, but the reference/desc
// text occasionally cites one — prefer it when present.
function firstCve(...texts: string[]): string | null {
  for (const t of texts) {
    const m = String(t ?? "").match(CVE_RE);
    if (m) return m[0].toUpperCase();
  }
  return null;
}

export type ZapFinding = {
  title: string;
  severity: Severity;
  cvss: number;
  asset: string;
  category: string;
  description: string;
  remediation: string;
  cve: string; // a referenced CVE if present, else ZAP-<cweid>
};

// Pulls the full JSON report ZAP currently holds (every site it has scanned,
// not just one target) — one finding per alert type per site, to avoid an
// explosion of near-duplicate rows per crawled instance. Read defensively:
// the report shape is large and any field may be missing or differently
// typed than documented.
export async function zapFetchReport(scope?: ZapScope): Promise<ZapFinding[]> {
  const config = scope?.config ?? zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/OTHER/core/other/jsonreport/", {}, 30_000);

  const out: ZapFinding[] = [];
  if (!Array.isArray(data?.site)) throw new Error("ZAP returned an invalid report site list.");
  const sites = data.site;
  let matched = false;
  for (const site of sites) {
    const siteUrl = String(site?.["@name"] ?? "");
    if (scope) {
      // The report is retained session evidence, not a fresh per-run snapshot.
      // Other customers' sites are deliberately ignored, never prefix-matched.
      if (scannerWebOrigin(siteUrl, true) !== scope.origin) continue;
      if (matched) throw new Error("ZAP report contains duplicate customer sites.");
      matched = true;
    }
    if (!Array.isArray(site?.alerts)) throw new Error("ZAP returned an invalid report alert list.");
    const alerts = site.alerts;
    for (const alert of alerts) {
      const severity = zapMapRiskToSeverity(alert?.riskcode);
      const cweid = String(alert?.cweid ?? "").trim();
      const instances = Array.isArray(alert?.instances) ? alert.instances : [];
      if (scope && (!Array.isArray(alert?.instances) || !instances.length || instances.some((item: any) =>
          typeof item?.uri !== "string" || scannerWebOrigin(item.uri) !== scope.origin)))
        throw new Error("ZAP alert evidence is missing or outside the customer origin.");
      const name = String(alert?.name ?? "ZAP finding");
      const instanceNote =
        instances.length > 1 ? ` Observed on ${instances.length} instances.` : "";
      const cve = firstCve(name, alert?.desc, alert?.reference);
      out.push({
        title: name,
        severity,
        cvss: severityCvss(severity),
        asset: siteUrl,
        category: "Web Vulnerability",
        description: `${String(alert?.desc ?? "Reported by OWASP ZAP.")}${instanceNote}${scope ? " Retained ZAP session evidence; this report can include earlier scans of this origin." : ""}`,
        remediation: String(alert?.solution ?? "See the ZAP alert detail for remediation."),
        cve:
          cve ??
          (cweid ? `ZAP-${cweid}` : `ZAP-${name.replace(/[^A-Za-z0-9]+/g, "-").toUpperCase()}`),
      });
    }
  }
  if (scope && !matched) throw new Error("ZAP returned no report for the approved origin; coverage is unknown.");
  return out;
}

function validZapId(value: unknown): boolean {
  return (typeof value === "string" || typeof value === "number") && /^(0|[1-9][0-9]*)$/.test(String(value)) && Number.isSafeInteger(Number(value));
}
export type ZapScope = { config: ZapConfig; origin: string; name: string; id: string };
// A private context prevents a shared session from broadening this launch.
// Contexts are retained on error so an operator can inspect any uncertain job.
export async function zapCreateScope(config: ZapConfig, target: string): Promise<ZapScope> {
  const origin = scannerWebOrigin(target, true), name = `gmi-${randomUUID()}`;
  const created = await zapFetch(config, "/JSON/context/action/newContext/", { contextName: name });
  if (!validZapId(created?.contextId)) throw new Error("ZAP context creation was not confirmed; inspect the scanner before retrying.");
  const id = String(created.contextId);
  const escaped = origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const included = await zapFetch(config, "/JSON/context/action/includeInContext/", { contextName: name, regex: `^${escaped}(?:/.*)?$` });
  if (included?.Result !== "OK") throw new Error("ZAP did not confirm the approved context scope.");
  return { config, origin, name, id };
}
export async function zapRemoveScope(scope: ZapScope): Promise<void> {
  const result = await zapFetch(scope.config, "/JSON/context/action/removeContext/", { contextName: scope.name });
  if (result?.Result !== "OK") throw new Error("ZAP context cleanup was not confirmed.");
}
