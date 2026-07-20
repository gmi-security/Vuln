import type { Severity } from "@/lib/types";

// Vulners adapter — two modes:
//
// 1. Cloud CVE enrichment (vulners.com or compatible self-hosted):
//      VULNERS_API_KEY   API key for vulners.com
//      VULNERS_URL       override base URL (default: https://vulners.com)
//
// 2. Vulners Bridge (VulnOps Core API — nmap --script vulners, run as an
//    async job: launch -> poll -> fetch findings):
//      VULNERS_BRIDGE_URL      base URL (with or without a trailing /api)
//      VULNERS_BRIDGE_API_KEY  a "vops_"-prefixed machine API key, sent as
//                               the X-API-Key header
//    Always launches the "vuln" scan profile — it's the only one that runs
//    the vulners NSE script; the others (discovery/quick/standard/full-tcp)
//    never produce a vulnerability finding.

export type VulnersConfig = {
  apiKey: string;
  baseUrl: string;
};

export function vulnersConfig(): VulnersConfig | null {
  const apiKey = process.env.VULNERS_API_KEY;
  if (!apiKey) return null;
  const baseUrl = (process.env.VULNERS_URL ?? "https://vulners.com").replace(/\/+$/, "");
  return { apiKey, baseUrl };
}

export type VulnersFinding = {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  epss: number;
  exploitAvailable: boolean;
  description: string;
  remediation: string;
  package: string; // affected package name
  installedVersion: string;
  fixedVersion: string;
  asset: string; // hostname the package came from
};

// Severity mapping from Vulners score bands.
function mapSeverity(cvss: number): Severity {
  if (cvss >= 9.0) return "Critical";
  if (cvss >= 7.0) return "High";
  if (cvss >= 4.0) return "Medium";
  if (cvss > 0) return "Low";
  return "Info";
}

// --- Vulners Bridge (VulnOps Core API, nmap active scanner) -----------------
export type VulnersBridgeConfig = { baseUrl: string; apiKey: string };

export function vulnersBridgeConfig(): VulnersBridgeConfig | null {
  const rawUrl = process.env.VULNERS_BRIDGE_URL?.trim();
  const apiKey = process.env.VULNERS_BRIDGE_API_KEY?.trim();
  if (!rawUrl || !apiKey) return null;
  // Accept the base URL with or without a trailing /api — every route below
  // is built as `${baseUrl}/api/...`, so normalize either form to the bare
  // host regardless of how it's configured.
  const baseUrl = rawUrl.replace(/\/+$/, "").replace(/\/api$/i, "");
  return { baseUrl, apiKey };
}

function describeBridgeFetchError(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as { cause?: unknown }).cause;
    if (err.name === "AbortError" || err.name === "TimeoutError") return "Request timed out.";
    if (cause instanceof Error) return cause.message;
    if (typeof cause === "string") return cause;
    return err.message;
  }
  return "Connection failed.";
}

async function bridgeFetch(
  cfg: VulnersBridgeConfig,
  path: string,
  init: { method?: string; body?: unknown; timeoutMs?: number } = {},
): Promise<any> {
  const res = await fetch(`${cfg.baseUrl}${path}`, {
    method: init.method ?? "GET",
    headers: {
      "X-API-Key": cfg.apiKey,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
    },
    body: init.body ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
    signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`Bridge ${path} HTTP ${res.status}: ${detail}`);
  }
  return res.json();
}

// Only the "vuln" profile runs the vulners NSE script — every other profile
// (discovery/quick/standard/full-tcp) exists on the platform for plain nmap
// use but would never produce a vulnerability finding through this connector.
const BRIDGE_SCAN_PROFILE = "vuln";

export type VulnersBridgeJob = { jobId: number; status: string };

export async function vulnersBridgeStartScan(
  target: string,
  scanName?: string,
): Promise<VulnersBridgeJob> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const data = await bridgeFetch(cfg, "/api/scan/execute", {
    method: "POST",
    body: { target, profile: BRIDGE_SCAN_PROFILE, scan_type: "nmap", scan_name: scanName },
    timeoutMs: 15_000,
  });
  const jobId = Number(data?.job_id);
  if (!Number.isFinite(jobId)) throw new Error("Bridge scan launch: no job_id returned.");
  return { jobId, status: String(data?.status ?? "queued") };
}

export type VulnersBridgeJobStatus = {
  status: "queued" | "running" | "complete" | "failed" | string;
  error: string | null;
};

export async function vulnersBridgeJobStatus(jobId: number): Promise<VulnersBridgeJobStatus> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const data = await bridgeFetch(cfg, `/api/scan/jobs/${jobId}`, { timeoutMs: 15_000 });
  return { status: String(data?.status ?? "unknown"), error: data?.error ?? null };
}

export type VulnersBridgeFinding = {
  cve: string;
  cvss: number;
  component: string; // e.g. "http (Port 80)"
  exploitAvailable: boolean;
  target: string;
};

// Pulls every finding row for a completed job and keeps only the real
// vulnerability hits (source: "vulners") — the same endpoint also returns
// one row per open port with source: "nmap" and no vuln_id, which is plain
// port noise this connector isn't meant to import.
export async function vulnersBridgeJobFindings(
  jobId: number,
  target: string,
): Promise<VulnersBridgeFinding[]> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const rows = await bridgeFetch(cfg, `/api/scan/jobs/${jobId}/findings`, { timeoutMs: 30_000 });
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((r: any) => r?.source === "vulners" && r?.vuln_id)
    .map((r: any) => ({
      cve: String(r.vuln_id).toUpperCase(),
      cvss: Number(r.cvss ?? 0),
      component: `${r.service ?? "service"} (Port ${r.port ?? "?"})`,
      exploitAvailable: false, // not provided by this API
      target: r.host ?? target,
    }))
    .filter((f: VulnersBridgeFinding) => f.cve.startsWith("CVE-"));
}

// --- Reachability probe -----------------------------------------------------
// Checks bridge first (if configured), then cloud API.
export async function vulnersStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const bridge = vulnersBridgeConfig();
  if (bridge) {
    try {
      // Cheap, static, auth-gated — a 200 here proves both reachability and
      // a valid API key with no side effects (no scan is triggered).
      await bridgeFetch(bridge, "/api/scan/config", { timeoutMs: 10_000 });
      return {
        configured: true,
        reachable: true,
        status: "Connected",
        message: "Vulners bridge reachable (nmap active scanner).",
      };
    } catch (err) {
      return {
        configured: true,
        reachable: false,
        status: "Unreachable",
        message: describeBridgeFetchError(err),
      };
    }
  }

  const config = vulnersConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message:
        "Set VULNERS_API_KEY for cloud CVE enrichment, or VULNERS_BRIDGE_URL + VULNERS_BRIDGE_API_KEY for the nmap active scanner.",
    };
  }
  try {
    const res = await fetch(`${config.baseUrl}/api/v3/search/lucene/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "type:cve", skip: 0, size: 1, apiKey: config.apiKey }),
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const ok = res.ok || res.status === 400;
    return {
      configured: true,
      reachable: ok,
      status: ok ? "Connected" : `HTTP ${res.status}`,
      message: ok ? "Vulners cloud API reachable." : await res.text().catch(() => res.statusText),
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

// --- Package audit -----------------------------------------------------------
// POST /api/v3/audit/audit — send OS + package list, receive CVE matches.
// Each entry in `packages` is a "name version" or "name-version.arch" string
// as reported by the host's package manager (rpm -qa, dpkg -l, etc.).
export async function vulnersAuditHost(
  hostname: string,
  os: string,
  packages: string[],
): Promise<VulnersFinding[]> {
  const config = vulnersConfig();
  if (!config) throw new Error("Vulners is not configured.");

  const body: Record<string, unknown> = {
    os,
    packages,
    apiKey: config.apiKey,
    version: "2",
  };

  const res = await fetch(`${config.baseUrl}/api/v3/audit/audit/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    throw new Error(`Vulners audit ${res.status}: ${await res.text().catch(() => res.statusText)}`);
  }
  const data: any = await res.json();
  if (data?.result !== "OK") {
    throw new Error(`Vulners audit error: ${data?.data?.error ?? JSON.stringify(data)}`);
  }

  const findings: VulnersFinding[] = [];
  const packages_obj: Record<string, any[]> = data?.data?.packages ?? {};
  for (const [pkg, vulns] of Object.entries(packages_obj)) {
    for (const v of vulns) {
      const cvss = Number(v?.cvss?.score ?? v?.cvss3?.cvssV3?.baseScore ?? 0);
      const cve = String(v?.id ?? v?.cvelist?.[0] ?? "").toUpperCase();
      if (!cve || !cve.startsWith("CVE-")) continue;
      findings.push({
        cve,
        title: String(v?.title ?? v?.id ?? pkg),
        severity: mapSeverity(cvss),
        cvss,
        epss: Number(v?.epss ?? 0),
        exploitAvailable: Boolean(v?.exploit_count ?? v?.exploits?.length ?? false),
        description: String(v?.description ?? `${pkg} affected by ${cve}`),
        remediation: String(v?.fix ?? `Upgrade ${pkg} to the fixed version.`),
        package: pkg,
        installedVersion: String(v?.package ?? ""),
        fixedVersion: String(v?.fix_in ?? ""),
        asset: hostname,
      });
    }
  }
  return findings;
}

// --- CVE enrichment ----------------------------------------------------------
// Look up one or more CVEs and return enriched data (CVSS, EPSS, description).
// Used to backfill metadata on findings that came from other scanners.
export type VulnersCveData = {
  id: string;
  cvss: number;
  epss: number;
  exploitAvailable: boolean;
  description: string;
};

export async function vulnersEnrichCves(cves: string[]): Promise<Map<string, VulnersCveData>> {
  const config = vulnersConfig();
  if (!config || !cves.length) return new Map();
  const out = new Map<string, VulnersCveData>();
  // Batch 50 at a time
  for (let i = 0; i < cves.length; i += 50) {
    const batch = cves.slice(i, i + 50);
    try {
      const res = await fetch(`${config.baseUrl}/api/v3/search/id/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: batch, apiKey: config.apiKey }),
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) continue;
      const data: any = await res.json();
      for (const doc of data?.data?.documents ?? []) {
        const id = String(doc?.id ?? "").toUpperCase();
        if (!id) continue;
        out.set(id, {
          id,
          cvss: Number(doc?.cvss?.score ?? doc?.cvss3?.cvssV3?.baseScore ?? 0),
          epss: Number(doc?.epss ?? 0),
          exploitAvailable: Boolean(doc?.exploit_count ?? doc?.exploits?.length ?? false),
          description: String(doc?.description ?? ""),
        });
      }
    } catch {
      continue;
    }
  }
  return out;
}
