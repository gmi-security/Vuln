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
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    throw new Error(`ZAP ${path} ${res.status}: ${await res.text().catch(() => res.statusText)}`);
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
      message: err instanceof Error ? err.message : "Connection failed.",
    };
  }
}

// --- Spider (crawl) ----------------------------------------------------------
export async function zapStartSpider(targetUrl: string): Promise<string> {
  const config = zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/JSON/spider/action/scan/", {
    url: targetUrl,
  });
  const scanId = data?.scan;
  if (scanId === undefined || scanId === null) {
    throw new Error("ZAP spider scan: no scan id returned.");
  }
  return String(scanId);
}

export async function zapSpiderStatus(scanId: string): Promise<number> {
  const config = zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/JSON/spider/view/status/", { scanId });
  const status = Number(data?.status);
  if (Number.isNaN(status)) throw new Error("ZAP spider status: malformed response.");
  return status;
}

// --- Active scan --------------------------------------------------------------
export async function zapStartActiveScan(targetUrl: string): Promise<string> {
  const config = zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/JSON/ascan/action/scan/", {
    url: targetUrl,
  });
  const scanId = data?.scan;
  if (scanId === undefined || scanId === null) {
    throw new Error("ZAP active scan: no scan id returned.");
  }
  return String(scanId);
}

export async function zapActiveScanStatus(scanId: string): Promise<number> {
  const config = zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/JSON/ascan/view/status/", { scanId });
  const status = Number(data?.status);
  if (Number.isNaN(status)) throw new Error("ZAP active scan status: malformed response.");
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
export async function zapFetchReport(): Promise<ZapFinding[]> {
  const config = zapConfig();
  if (!config) throw new Error("ZAP is not configured. Set ZAP_URL and ZAP_API_KEY.");
  const data = await zapFetch(config, "/OTHER/core/other/jsonreport/", {}, 30_000);

  const out: ZapFinding[] = [];
  const sites = Array.isArray(data?.site) ? data.site : [];
  for (const site of sites) {
    const siteUrl = String(site?.["@name"] ?? "");
    const alerts = Array.isArray(site?.alerts) ? site.alerts : [];
    for (const alert of alerts) {
      const severity = zapMapRiskToSeverity(alert?.riskcode);
      const cweid = String(alert?.cweid ?? "").trim();
      const instances = Array.isArray(alert?.instances) ? alert.instances : [];
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
        description: `${String(alert?.desc ?? "Reported by OWASP ZAP.")}${instanceNote}`,
        remediation: String(alert?.solution ?? "See the ZAP alert detail for remediation."),
        cve:
          cve ??
          (cweid ? `ZAP-${cweid}` : `ZAP-${name.replace(/[^A-Za-z0-9]+/g, "-").toUpperCase()}`),
      });
    }
  }
  return out;
}
