import type { Severity } from "@/lib/types";

// Vulners adapter — two modes:
//
// 1. Cloud CVE enrichment (vulners.com or compatible self-hosted):
//      VULNERS_API_KEY   API key for vulners.com
//      VULNERS_URL       override base URL (default: https://vulners.com)
//
// 2. Vulners Bridge (GMI Vuln API — a Greenbone/OpenVAS-backed scanner, run
//    as an async task: create scan -> start -> poll -> fetch findings).
//    Two independent credential pairs are recognized for this — they are
//    two separate bridge deployments, not a combined requirement, and
//    neither is touched/overwritten by the other:
//      GMI_SCANNER_URL / GMI_SCANNER_API_KEY        checked first
//      VULNERS_BRIDGE_URL / VULNERS_BRIDGE_API_KEY  fallback if unset
//    Both send the key as the X-API-Key header against the same route
//    shape (base URL with or without a trailing /api).
//    Launches the "full-fast" scan config against the target host(s); this
//    is the same config GMI's own scanner validation runs use.

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

// --- Vulners Bridge (GMI Vuln API, Greenbone/OpenVAS active scanner) -------
export type VulnersBridgeConfig = { baseUrl: string; apiKey: string };

export function vulnersBridgeConfig(): VulnersBridgeConfig | null {
  const rawUrl = process.env.GMI_SCANNER_URL?.trim() || process.env.VULNERS_BRIDGE_URL?.trim();
  const apiKey = process.env.GMI_SCANNER_API_KEY?.trim() || process.env.VULNERS_BRIDGE_API_KEY?.trim();
  if (!rawUrl || !apiKey) return null;
  // Accept the base URL with or without a trailing /api — every route below
  // is built as `${baseUrl}/api/...`, so normalize either form to the bare
  // host regardless of how it's configured.
  const baseUrl = rawUrl.replace(/\/+$/, "").replace(/\/api$/i, "");
  return { baseUrl, apiKey };
}

function bridgeHealthError(err: unknown): { authError: boolean; checkError: boolean; message: string } {
  const status = err && typeof err === "object" && "httpStatus" in err ? err.httpStatus : null;
  if (status === 401 || status === 403) return { authError: true, checkError: false, message: "Bridge credentials rejected." };
  if (typeof status === "number" && status >= 400 && status < 500) return { authError: false, checkError: true, message: "Bridge health check rejected." };
  if (err instanceof Error && (err.name === "AbortError" || err.name === "TimeoutError")) {
    return { authError: false, checkError: false, message: "Bridge request timed out." };
  }
  return { authError: false, checkError: false, message: "Bridge unavailable." };
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
    throw Object.assign(new Error(`Bridge ${path} HTTP ${res.status}: ${detail}`), { httpStatus: res.status });
  }
  return res.json();
}

const BRIDGE_SCAN_PROFILE = "full-fast";

export type VulnersBridgeJob = { jobId: string; status: string };

export async function vulnersBridgeStartScan(
  target: string,
  scanName?: string,
): Promise<VulnersBridgeJob> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const created = await bridgeFetch(cfg, "/api/v1/scans", {
    method: "POST",
    body: { name: scanName || `GMI scan: ${target}`, hosts: [target], profile: BRIDGE_SCAN_PROFILE },
    timeoutMs: 15_000,
  });
  // The create response uses "task_id" (confirmed against a live call);
  // every other endpoint (GET /scans/{id}, /start) uses plain "id" for the
  // same value. Reading created?.id here silently returned undefined,
  // which made every real scan throw immediately after creation and get
  // swallowed by the caller's per-target catch -- "Completed, 0 findings"
  // for every target, every time, with no visible error anywhere.
  const jobId = String(created?.task_id ?? created?.id ?? "");
  if (!jobId) throw new Error("Bridge scan launch: no scan id returned.");
  const started = await bridgeFetch(cfg, `/api/v1/scans/${encodeURIComponent(jobId)}/start`, {
    method: "POST",
    body: { authorization_confirmed: true },
    timeoutMs: 15_000,
  });
  return { jobId, status: mapBridgeStatus(started?.status ?? created?.status) };
}

export type VulnersBridgeJobStatus = {
  status: "queued" | "running" | "complete" | "failed" | string;
  error: string | null;
};

// GVM task statuses ("New", "Requested", "Running", "Stop Requested",
// "Stopped", "Interrupted", "Done") collapsed to the four states the poll
// loop in lib/store.ts understands.
function mapBridgeStatus(raw: unknown): "queued" | "running" | "complete" | "failed" {
  const s = String(raw ?? "").toLowerCase();
  if (s === "done") return "complete";
  if (s === "running") return "running";
  // "new"/"requested" are the task-creation-flow values seen on the create
  // and /start responses; "queued" is what a live poll of GET
  // /api/v1/scans/{id} actually returns before the scanner picks it up --
  // confirmed against a real response, not assumed from generic GVM
  // status docs. Missing it here meant every scan was misclassified as
  // failed on its very first poll, before ever getting a chance to run.
  if (s === "new" || s === "requested" || s === "queued") return "queued";
  return "failed";
}

export async function vulnersBridgeJobStatus(jobId: string): Promise<VulnersBridgeJobStatus> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const data = await bridgeFetch(cfg, `/api/v1/scans/${encodeURIComponent(jobId)}`, { timeoutMs: 15_000 });
  const status = mapBridgeStatus(data?.status);
  return { status, error: status === "failed" ? `Scan status: ${data?.status ?? "unknown"}` : null };
}

export type VulnersBridgeFinding = {
  cve: string;
  cvss: number;
  component: string; // e.g. "Allowed HTTP Methods Enumeration (Port 443)"
  exploitAvailable: boolean;
  target: string;
};

// Pulls every finding row for a completed scan. Each row can carry zero or
// more CVEs (via its `cves` array) — rows with none are OpenVAS recon/log
// entries (open ports, banners, TLS config, etc.), not vulnerability hits,
// so they're dropped. A row with multiple CVEs is emitted once per CVE,
// sharing that row's severity.
export async function vulnersBridgeJobFindings(
  jobId: string,
  target: string,
): Promise<VulnersBridgeFinding[]> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const data = await bridgeFetch(cfg, `/api/v1/scans/${encodeURIComponent(jobId)}/findings`, { timeoutMs: 30_000 });
  const rows = Array.isArray(data?.findings) ? data.findings : [];
  const out: VulnersBridgeFinding[] = [];
  for (const r of rows) {
    const cves = Array.isArray(r?.cves) ? r.cves : [];
    if (!cves.length) continue;
    const portNum = String(r?.port ?? "").match(/^(\d+)/)?.[1] ?? r?.port ?? "?";
    const component = `${r?.name ?? r?.nvt_name ?? "service"} (Port ${portNum})`;
    const cvss = Number(r?.severity ?? 0);
    const host = r?.host ?? target;
    for (const c of cves) {
      const cve = String(typeof c === "string" ? c : c?.id ?? c?.cve ?? "").toUpperCase();
      if (!cve.startsWith("CVE-")) continue;
      out.push({ cve, cvss, component, exploitAvailable: false, target: host });
    }
  }
  return out;
}

// --- Reachability probe -----------------------------------------------------
// Checks bridge first (if configured), then cloud API.
export async function vulnersStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
  authError: boolean;
  checkError: boolean;
}> {
  const bridge = vulnersBridgeConfig();
  if (bridge) {
    try {
      // Cheap, read-only, auth-gated — a 200 here proves both reachability
      // and a valid API key with no side effects (no scan is triggered).
      await bridgeFetch(bridge, "/api/v1/scanners", { timeoutMs: 10_000 });
      return {
        configured: true,
        reachable: true,
        status: "Connected",
        message: "Vulners bridge reachable (OpenVAS active scanner).",
        authError: false,
        checkError: false,
      };
    } catch (err) {
      return {
        configured: true,
        reachable: false,
        status: "Unreachable",
        ...bridgeHealthError(err),
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
      authError: false,
      checkError: false,
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
      message: ok ? "Vulners cloud API reachable." : `Vulners cloud API returned HTTP ${res.status}.`,
      authError: res.status === 401 || res.status === 403,
      checkError: res.status >= 400 && res.status < 500 && res.status !== 401 && res.status !== 403,
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: "Vulners cloud API unavailable.",
      authError: false,
      checkError: false,
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
