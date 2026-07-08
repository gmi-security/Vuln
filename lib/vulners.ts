import type { Severity } from "@/lib/types";

// Vulners adapter — two modes:
//
// 1. Cloud CVE enrichment (vulners.com or compatible self-hosted):
//      VULNERS_API_KEY   API key for vulners.com
//      VULNERS_URL       override base URL (default: https://vulners.com)
//
// 2. Vulners Bridge (nmap --script vulners active scanner):
//      VULNERS_BRIDGE_URL    http://<host>:8000
//      VULNERS_BRIDGE_USER   username (default: admin)
//      VULNERS_BRIDGE_PASS   password
//    The bridge runs nmap -sV --script vulners against a target IP and
//    returns CVEs matched to the detected service versions.

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

// --- Vulners Bridge (nmap active scanner) ------------------------------------
export type VulnersBridgeConfig = {
  url: string;
  user: string;
  pass: string;
};

export function vulnersBridgeConfig(): VulnersBridgeConfig | null {
  const url = process.env.VULNERS_BRIDGE_URL?.trim();
  const pass = process.env.VULNERS_BRIDGE_PASS?.trim();
  if (!url || !pass) return null;
  return {
    url: url.replace(/\/+$/, ""),
    user: process.env.VULNERS_BRIDGE_USER?.trim() || "admin",
    pass,
  };
}

export type VulnersBridgeFinding = {
  cve: string;
  cvss: number;
  component: string; // e.g. "HTTP (Port 80)"
  exploitAvailable: boolean;
  target: string;
};

async function bridgeLogin(cfg: VulnersBridgeConfig): Promise<string> {
  const res = await fetch(`${cfg.url}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: cfg.user, password: cfg.pass }),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Bridge login failed: HTTP ${res.status}`);
  const data: any = await res.json();
  if (!data?.access_token) throw new Error("Bridge login: no access_token returned");
  return data.access_token;
}

// Trigger an nmap --script vulners scan against one target via the bridge.
export async function vulnersBridgeScanHost(target: string): Promise<VulnersBridgeFinding[]> {
  const cfg = vulnersBridgeConfig();
  if (!cfg) throw new Error("Vulners bridge is not configured.");
  const token = await bridgeLogin(cfg);
  const res = await fetch(`${cfg.url}/api/scan?target=${encodeURIComponent(target)}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(
      `Bridge scan ${res.status}: ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const data: any = await res.json();
  return (data?.vulnerabilities ?? [])
    .map((v: any) => ({
      cve: String(v?.cve ?? "").toUpperCase(),
      cvss: Number(v?.cvss ?? 0),
      component: String(v?.component ?? ""),
      exploitAvailable: String(v?.status ?? "").toLowerCase().includes("exploit"),
      target,
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
      await bridgeLogin(bridge);
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
        message: err instanceof Error ? err.message : "Bridge connection failed.",
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
        "Set VULNERS_API_KEY for cloud CVE enrichment, or VULNERS_BRIDGE_URL + VULNERS_BRIDGE_PASS for the nmap active scanner.",
    };
  }
  try {
    const res = await fetch(`${config.baseUrl}/api/v3/search/lucene/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "type:cve", skip: 0, size: 1, apiKey: config.apiKey }),
      cache: "no-store",
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
