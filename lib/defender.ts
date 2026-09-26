import type { Severity } from "@/lib/types";

// Microsoft Defender Vulnerability Management adapter.
//
// Pulls per-device CVE findings from Microsoft Defender for Endpoint / Defender
// Vulnerability Management via the Security API (app-only / client
// credentials). This is the "vuln perspective" for a Defender-managed estate —
// analogous to CrowdStrike Spotlight.
//
// Configure with an Entra app granted Vulnerability.Read.All (WindowsDefenderATP):
//   DEFENDER_TENANT_ID     directory (tenant) id
//   DEFENDER_CLIENT_ID     app (client) id
//   DEFENDER_CLIENT_SECRET client secret
//
// Also grant Machine.Read.All if you want Defender's findings to link up
// with other scanners that see the same device under a different IP or
// hostname (e.g. an external scanner hitting its public IP) — it's optional;
// without it, findings still import fine, just without those extra aliases.

export type DefenderConfig = {
  tenantId: string;
  clientId: string;
  clientSecret: string;
};

export function defenderConfig(): DefenderConfig | null {
  const tenantId = process.env.DEFENDER_TENANT_ID;
  const clientId = process.env.DEFENDER_CLIENT_ID;
  const clientSecret = process.env.DEFENDER_CLIENT_SECRET;
  if (!tenantId || !clientId || !clientSecret) return null;
  return { tenantId, clientId, clientSecret };
}

export type DefenderFinding = {
  cve: string;
  title: string;
  severity: Severity;
  cvss: number;
  asset: string;
  // Every identifier Defender has for this device (device name, internal
  // IP, external IP) — lets the store link them as the same device even
  // when another connector only reports one of them. Only the device name
  // is guaranteed; the IPs depend on Machine.Read.All being granted.
  assetAliases: string[];
  category: string;
  description: string;
  remediation: string;
};

const API_BASE = "https://api.securitycenter.microsoft.com";

function mapSeverity(raw: unknown): Severity {
  const v = String(raw ?? "").toLowerCase();
  if (v === "critical") return "Critical";
  if (v === "high") return "High";
  if (v === "medium") return "Medium";
  if (v === "low") return "Low";
  return "Info";
}

async function defenderToken(config: DefenderConfig): Promise<string> {
  const res = await fetch(
    `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: `${API_BASE}/.default`,
        grant_type: "client_credentials",
      }),
      cache: "no-store",
    },
  );
  if (!res.ok) {
    throw new Error(
      `Defender auth failed: ${res.status} ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) throw new Error("Defender auth returned no token.");
  return data.access_token;
}

type DefenderMachine = { name: string; ip: string; externalIp: string };

// Machine device name + IPs, keyed by machine id. Best-effort: a tenant may
// have granted Vulnerability.Read.All without also granting Machine.Read.All,
// in which case this throws and the caller proceeds with device names only —
// the core vulnerability import must never fail just because the optional
// identity-linking context isn't available.
async function defenderListMachines(token: string): Promise<Map<string, DefenderMachine>> {
  const machines = new Map<string, DefenderMachine>();
  let url: string | null = `${API_BASE}/api/machines`;
  let guard = 0;
  while (url && guard < 200) {
    guard += 1;
    const res: Response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(
        `Defender machines API ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const data: any = await res.json();
    for (const m of data?.value ?? []) {
      const id = String(m?.id ?? "");
      if (!id) continue;
      machines.set(id, {
        name: String(m?.computerDnsName ?? ""),
        ip: String(m?.lastIpAddress ?? ""),
        externalIp: String(m?.lastExternalIpAddress ?? ""),
      });
    }
    url = data?.["@odata.nextLink"] ?? null;
  }
  return machines;
}

// List software vulnerabilities per device, following @odata.nextLink paging.
export async function defenderListFindings(): Promise<DefenderFinding[]> {
  const config = defenderConfig();
  if (!config) throw new Error("Defender is not configured.");
  const token = await defenderToken(config);
  let machines = new Map<string, DefenderMachine>();
  try {
    machines = await defenderListMachines(token);
  } catch {
    // Machine.Read.All not granted, or the machines API is unreachable —
    // findings still import fine, just without the extra IP aliases.
  }

  const findings: DefenderFinding[] = [];
  let url: string | null = `${API_BASE}/api/machines/SoftwareVulnerabilitiesByMachine`;
  let guard = 0;
  while (url && guard < 200) {
    guard += 1;
    const res: Response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(
        `Defender API ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const data: any = await res.json();
    for (const v of data?.value ?? []) {
      const cve = String(v?.cveId ?? "");
      const asset = String(v?.deviceName ?? v?.machineId ?? "");
      if (!cve || !asset) continue;
      const software = [v?.softwareVendor, v?.softwareName]
        .filter(Boolean)
        .join(" ");
      const machine = machines.get(String(v?.machineId ?? ""));
      const assetAliases = [...new Set([asset, machine?.name, machine?.ip, machine?.externalIp]
        .filter((x): x is string => Boolean(x)))];
      findings.push({
        cve,
        title: software ? `${software} — ${cve}` : cve,
        severity: mapSeverity(v?.vulnerabilitySeverityLevel),
        cvss: Number(v?.cvssV3 ?? 0),
        asset,
        assetAliases,
        category: "Endpoint",
        description: `Vulnerability ${cve} detected by Microsoft Defender on ${asset}${software ? ` (${software})` : ""}.`,
        remediation: String(
          v?.recommendedSecurityUpdate ??
            v?.recommendedSecurityUpdateId ??
            "Apply the vendor security update; see Defender security recommendations.",
        ),
      });
    }
    url = data?.["@odata.nextLink"] ?? null;
  }
  return findings;
}
