import type { AssetCriticality, AssetExposure, Severity } from "@/lib/types";

// CrowdStrike Falcon device-inventory adapter.
//
// The existing CrowdStrike scanner connector imports Spotlight vulnerabilities
// (the "vuln perspective"). This adapter pulls the Falcon host inventory (the
// "scan / coverage perspective") — which endpoints have a sensor — so devices
// become known assets in the coverage diff and their Spotlight findings attach
// to them. Uses the same FALCON_* credentials as the scanner connector.

export type FalconConfig = {
  clientId: string;
  clientSecret: string;
  baseUrl: string;
};

const CLOUD_HOSTS: Record<string, string> = {
  "us-1": "https://api.crowdstrike.com",
  us1: "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  us2: "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  eu1: "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
};

export function falconConfig(): FalconConfig | null {
  const clientId = process.env.FALCON_CLIENT_ID;
  const clientSecret = process.env.FALCON_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  const cloud = (process.env.FALCON_CLOUD ?? "us-1").toLowerCase();
  return {
    clientId,
    clientSecret,
    baseUrl: CLOUD_HOSTS[cloud] ?? "https://api.crowdstrike.com",
  };
}

export type FalconAsset = {
  externalId: string;
  hostname: string;
  ipAddresses: string[];
  os: string;
  owner: string;
  tags: string[];
  criticality: AssetCriticality;
  exposure: AssetExposure;
};

async function falconToken(config: FalconConfig): Promise<string> {
  const res = await fetch(`${config.baseUrl}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(
      `Falcon auth failed: ${res.status} ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) throw new Error("Falcon auth returned no token.");
  return data.access_token;
}

function classifyHost(raw: any): {
  exposure: AssetExposure;
  criticality: AssetCriticality;
} {
  const product = String(raw?.product_type_desc ?? "").toLowerCase();
  const os = String(raw?.os_version ?? raw?.platform_name ?? "").toLowerCase();
  const criticality: AssetCriticality =
    product === "server" || /server/.test(os) ? "High" : "Normal";
  return { exposure: "Internal", criticality };
}

function normalizeFalconHost(raw: any): FalconAsset {
  const { exposure, criticality } = classifyHost(raw);
  const os = [raw?.platform_name, raw?.os_version].filter(Boolean).join(" ");
  const ips = [raw?.local_ip, raw?.external_ip]
    .filter(Boolean)
    .map((x: unknown) => String(x));
  return {
    externalId: String(raw?.device_id ?? raw?.cid ?? ""),
    hostname: String(raw?.hostname ?? ""),
    ipAddresses: ips,
    os,
    owner: String(raw?.machine_domain ?? raw?.last_login_user ?? ""),
    tags: []
      .concat(raw?.tags ?? [])
      .flat()
      .map((x: unknown) => String(x))
      .filter(Boolean),
    criticality,
    exposure,
  };
}

// --- Spotlight vulnerability findings ----------------------------------------

export type SpotlightFinding = {
  cve: string;
  hostname: string;
  localIp: string;
  externalIp: string;
  os: string;
  severity: Severity;
  cvss: number;
  title: string;
  description: string;
  remediation: string;
  exploitAvailable: boolean;
  status: string; // "open" | "reopen" | etc.
  exprRating: string; // CrowdStrike ExPRT score label
};

const EXPRT_SEV: Record<string, Severity> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

// CrowdStrike Spotlight API: query open vuln ids, hydrate in batches of 400.
// Requires scope: spotlight-vulnerabilities:read.
export async function spotlightListFindings(): Promise<SpotlightFinding[]> {
  const config = falconConfig();
  if (!config) throw new Error("CrowdStrike is not configured.");
  const token = await falconToken(config);
  const authHeader = { Authorization: `Bearer ${token}`, Accept: "application/json" };

  // Cursor-based ID pagination — must be sequential (each page depends on prior cursor).
  const ids: string[] = [];
  let after = "";
  let guard = 0;
  while (guard < 200) {
    guard += 1;
    const url = new URL(`${config.baseUrl}/spotlight/queries/vulnerabilities/v1`);
    url.searchParams.set("filter", "status:'open',status:'reopen'");
    url.searchParams.set("limit", "400");
    if (after) url.searchParams.set("after", after);
    const r = await fetch(url.toString(), { headers: authHeader, cache: "no-store" });
    if (!r.ok) {
      throw new Error(`Spotlight query ${r.status}: ${await r.text().catch(() => r.statusText)}`);
    }
    const j: any = await r.json();
    const batch: string[] = j?.resources ?? [];
    ids.push(...batch);
    after = j?.meta?.pagination?.after ?? "";
    if (!after || !batch.length) break;
  }

  if (!ids.length) return [];

  // Build entity-fetch tasks for all 400-ID batches, then run them in parallel.
  const batches: string[][] = [];
  for (let i = 0; i < ids.length; i += 400) batches.push(ids.slice(i, i + 400));

  const parseResource = (v: any): SpotlightFinding => {
    const cve = String(v?.cve?.id ?? "").toUpperCase() || `CS-${v?.id ?? "vuln"}`;
    const sev: Severity =
      EXPRT_SEV[String(v?.cve?.exprt_rating ?? v?.severity ?? "").toUpperCase()] ?? "Medium";
    const cvss = Number(v?.cve?.cvss_v3 ?? v?.cve?.cvss_v2 ?? 5.0);
    return {
      cve,
      hostname: String(v?.host_info?.hostname ?? ""),
      localIp: String(v?.host_info?.local_ip ?? ""),
      externalIp: String(v?.host_info?.external_ip ?? ""),
      os: String(v?.host_info?.os_version ?? v?.host_info?.platform ?? ""),
      severity: sev,
      cvss: isNaN(cvss) ? 5.0 : cvss,
      title: String(v?.cve?.description ?? v?.cve?.id ?? "CrowdStrike Spotlight finding"),
      description: String(v?.cve?.description ?? "Reported by CrowdStrike Falcon Spotlight."),
      remediation: String(v?.remediation?.entities?.[0]?.action ?? "Apply vendor patch."),
      exploitAvailable: Boolean(v?.cve?.exploit_status ?? false),
      status: String(v?.status ?? "open"),
      exprRating: String(v?.cve?.exprt_rating ?? ""),
    };
  };

  const results = await Promise.all(
    batches.map(async (batch) => {
      const r = await fetch(
        `${config.baseUrl}/spotlight/entities/vulnerabilities/v2?ids=${batch.join("&ids=")}`,
        { headers: authHeader, cache: "no-store" },
      );
      if (!r.ok) {
        throw new Error(`Spotlight entities ${r.status}: ${await r.text().catch(() => r.statusText)}`);
      }
      const j: any = await r.json();
      return (j?.resources ?? []).map(parseResource) as SpotlightFinding[];
    }),
  );
  return results.flat();
}

// --- Falcon host inventory ---------------------------------------------------
// List Falcon hosts: query device ids (first page gives total → remaining pages
// fire in parallel), then hydrate all ID batches in parallel.
export async function falconListAssets(): Promise<FalconAsset[]> {
  const config = falconConfig();
  if (!config) throw new Error("CrowdStrike is not configured.");
  const token = await falconToken(config);
  const authHeader = { Authorization: `Bearer ${token}`, Accept: "application/json" };

  const PAGE = 500;

  const fetchIdPage = async (offset: number): Promise<{ ids: string[]; total: number }> => {
    const r = await fetch(
      `${config.baseUrl}/devices/queries/devices/v1?limit=${PAGE}&offset=${offset}`,
      { headers: authHeader, cache: "no-store" },
    );
    if (!r.ok) {
      throw new Error(
        `Falcon devices query ${r.status}: ${await r.text().catch(() => r.statusText)}`,
      );
    }
    const j: any = await r.json();
    return {
      ids: j?.resources ?? [],
      total: j?.meta?.pagination?.total ?? 0,
    };
  };

  const hydrateIds = async (ids: string[]): Promise<FalconAsset[]> => {
    const r = await fetch(`${config.baseUrl}/devices/entities/devices/v2`, {
      method: "POST",
      headers: { ...authHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
      cache: "no-store",
    });
    if (!r.ok) {
      throw new Error(
        `Falcon devices entities ${r.status}: ${await r.text().catch(() => r.statusText)}`,
      );
    }
    const j: any = await r.json();
    return (j?.resources ?? [])
      .map(normalizeFalconHost)
      .filter((a: FalconAsset) => a.hostname);
  };

  // Fetch first page to learn the total, then fire remaining pages in parallel.
  const first = await fetchIdPage(0);
  if (!first.ids.length) return [];

  const total = first.total || first.ids.length;
  const remainingOffsets: number[] = [];
  for (let off = PAGE; off < total; off += PAGE) remainingOffsets.push(off);

  const restPages = await Promise.all(remainingOffsets.map((off) => fetchIdPage(off)));
  const allIds = [first.ids, ...restPages.map((p) => p.ids)].flat();

  // Hydrate all ID batches in parallel (API accepts up to 500 per POST).
  const idBatches: string[][] = [];
  for (let i = 0; i < allIds.length; i += PAGE) idBatches.push(allIds.slice(i, i + PAGE));

  const results = await Promise.all(idBatches.map(hydrateIds));
  return results.flat();
}
