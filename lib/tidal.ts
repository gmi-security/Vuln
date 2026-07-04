import type { AssetCriticality, AssetExposure } from "@/lib/types";

// Tidal.io asset-inventory adapter.
//
// Tidal.io is an IT lifecycle / asset-management platform: it holds the
// authoritative per-customer asset inventory (hostname, addresses, owner,
// business criticality, environment). We pull that inventory and use it as
// the environmental context for real-risk scoring — replacing hostname
// heuristics with real ownership + criticality data.
//
// Configure with:
//   TIDAL_API_URL      base URL of the Tidal API (e.g. https://api.tidal.io)
//   TIDAL_API_KEY      API token (from the portal Profile → Settings page)
//   TIDAL_PROFILE_ID   the profile/tenant id in the portal URL (optional)
//   TIDAL_ASSETS_PATH  override the assets endpoint path (optional)

export type TidalConfig = {
  url: string;
  apiKey: string;
  profileId: string;
  assetsPath: string;
};

export function tidalConfig(): TidalConfig | null {
  const url = process.env.TIDAL_API_URL;
  const apiKey = process.env.TIDAL_API_KEY;
  if (!url || !apiKey) return null;
  return {
    url: url.replace(/\/+$/, ""),
    apiKey,
    profileId: process.env.TIDAL_PROFILE_ID ?? "",
    assetsPath: process.env.TIDAL_ASSETS_PATH ?? "/v1/assets",
  };
}

// Normalized asset shape the store consumes, independent of Tidal's exact
// payload field names.
export type TidalAsset = {
  externalId: string;
  hostname: string;
  ipAddresses: string[];
  os: string;
  owner: string;
  customer: string; // maps onto a Vuln company
  tags: string[];
  criticality: AssetCriticality;
  exposure: AssetExposure;
};

function mapCriticality(raw: unknown): AssetCriticality {
  const v = String(raw ?? "").toLowerCase();
  if (/(crown|tier\s*0|mission|critical|business.?critical)/.test(v)) return "Crown Jewel";
  if (/(high|tier\s*1|important)/.test(v)) return "High";
  if (/(low|tier\s*3|minimal|dev|test)/.test(v)) return "Low";
  return "Normal";
}

function mapExposure(raw: unknown): AssetExposure {
  const v = String(raw ?? "").toLowerCase();
  if (/(internet|external|public|dmz|perimeter|edge)/.test(v)) return "Internet-facing";
  if (/(isolated|air.?gap|ot|scada|segmented)/.test(v)) return "Isolated";
  return "Internal";
}

// Best-effort normalizer over a loosely-typed Tidal asset record. Reads the
// common field names; adjust here once the exact payload is confirmed.
export function normalizeTidalAsset(raw: any): TidalAsset {
  const ips: string[] = []
    .concat(raw?.ip_addresses ?? raw?.ipAddresses ?? raw?.ips ?? raw?.ip ?? [])
    .flat()
    .map((x: unknown) => String(x))
    .filter(Boolean);
  return {
    externalId: String(raw?.id ?? raw?.asset_id ?? raw?.uuid ?? ""),
    hostname: String(raw?.hostname ?? raw?.name ?? raw?.fqdn ?? raw?.host ?? ""),
    ipAddresses: ips,
    os: String(raw?.os ?? raw?.operating_system ?? raw?.platform ?? ""),
    owner: String(raw?.owner ?? raw?.owner_name ?? raw?.assigned_to ?? ""),
    customer: String(
      raw?.customer ?? raw?.customer_name ?? raw?.account ?? raw?.organization ?? raw?.org ?? "",
    ),
    tags: []
      .concat(raw?.tags ?? raw?.labels ?? [])
      .flat()
      .map((x: unknown) => String(x))
      .filter(Boolean),
    criticality: mapCriticality(
      raw?.criticality ?? raw?.business_criticality ?? raw?.importance ?? raw?.tier,
    ),
    exposure: mapExposure(
      raw?.exposure ?? raw?.environment ?? raw?.network_zone ?? raw?.zone ?? raw?.facing,
    ),
  };
}

// Fetch the asset inventory from Tidal. Paginates on `next` / offset when the
// API provides it; returns normalized assets.
export async function tidalListAssets(): Promise<TidalAsset[]> {
  const config = tidalConfig();
  if (!config) throw new Error("Tidal is not configured.");

  const headers = {
    Authorization: `Bearer ${config.apiKey}`,
    Accept: "application/json",
    ...(config.profileId ? { "X-Tidal-Profile": config.profileId } : {}),
  };

  const assets: TidalAsset[] = [];
  let url: string | null = `${config.url}${config.assetsPath}?limit=200`;
  let guard = 0;
  while (url && guard < 50) {
    guard += 1;
    const res: Response = await fetch(url, { headers, cache: "no-store" });
    if (!res.ok) {
      throw new Error(`Tidal ${res.status}: ${await res.text().catch(() => res.statusText)}`);
    }
    const data: any = await res.json();
    const records: any[] = Array.isArray(data)
      ? data
      : data?.data ?? data?.assets ?? data?.results ?? data?.items ?? [];
    for (const r of records) assets.push(normalizeTidalAsset(r));

    const next = data?.links?.next ?? data?.next ?? data?.next_page ?? null;
    url = next ? (String(next).startsWith("http") ? String(next) : `${config.url}${next}`) : null;
  }
  return assets;
}
