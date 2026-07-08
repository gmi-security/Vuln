import type { Severity } from "@/lib/types";

// Vulners adapter — vulnerability intelligence & package audit.
//
// Supports both the Vulners cloud API (vulners.com) and a self-hosted
// instance. Configure with:
//   VULNERS_API_KEY   API key
//   VULNERS_URL       base URL (default: https://vulners.com — override for
//                     self-hosted, e.g. http://165.245.174.129:5173)
//
// The primary use-case is the /audit endpoint: given a list of installed
// packages per host, Vulners returns CVEs that affect them. This can be
// driven against the asset inventory's known OS/packages.

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

// --- Reachability probe -----------------------------------------------------
export async function vulnersStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const config = vulnersConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set VULNERS_API_KEY and optionally VULNERS_URL for a self-hosted instance.",
    };
  }
  try {
    const res = await fetch(`${config.baseUrl}/api/v3/search/lucene/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "type:cve", skip: 0, size: 1, apiKey: config.apiKey }),
      cache: "no-store",
    });
    const ok = res.ok || res.status === 400; // 400 = reached but bad params (still reachable)
    return {
      configured: true,
      reachable: ok,
      status: ok ? "Connected" : `HTTP ${res.status}`,
      message: ok ? "Vulners API reachable." : await res.text().catch(() => res.statusText),
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
