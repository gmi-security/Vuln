import type { AssetCriticality, AssetExposure } from "@/lib/types";

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

// List Falcon hosts: query device ids, then hydrate details in batches.
export async function falconListAssets(): Promise<FalconAsset[]> {
  const config = falconConfig();
  if (!config) throw new Error("CrowdStrike is not configured.");
  const token = await falconToken(config);
  const authHeader = { Authorization: `Bearer ${token}`, Accept: "application/json" };

  const assets: FalconAsset[] = [];
  let offset = 0;
  let guard = 0;
  while (guard < 100) {
    guard += 1;
    const q: Response = await fetch(
      `${config.baseUrl}/devices/queries/devices/v1?limit=500&offset=${offset}`,
      { headers: authHeader, cache: "no-store" },
    );
    if (!q.ok) {
      throw new Error(
        `Falcon devices query ${q.status}: ${await q.text().catch(() => q.statusText)}`,
      );
    }
    const qData: any = await q.json();
    const ids: string[] = qData?.resources ?? [];
    if (!ids.length) break;

    // Hydrate device details.
    const d: Response = await fetch(`${config.baseUrl}/devices/entities/devices/v2`, {
      method: "POST",
      headers: { ...authHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
      cache: "no-store",
    });
    if (!d.ok) {
      throw new Error(
        `Falcon devices entities ${d.status}: ${await d.text().catch(() => d.statusText)}`,
      );
    }
    const dData: any = await d.json();
    for (const host of dData?.resources ?? []) {
      const asset = normalizeFalconHost(host);
      if (asset.hostname) assets.push(asset);
    }

    const total: number = qData?.meta?.pagination?.total ?? ids.length;
    offset += ids.length;
    if (offset >= total) break;
  }
  return assets;
}
