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
  username: string;
  password: string;
  apiKey: string; // optional static token (skips the credential sign-in)
  assetsPath: string;
};

export function tidalConfig(): TidalConfig | null {
  const url = process.env.TIDAL_API_URL;
  const username = process.env.TIDAL_USERNAME ?? process.env.TIDAL_EMAIL ?? "";
  const password = process.env.TIDAL_PASSWORD ?? "";
  const apiKey = process.env.TIDAL_API_KEY ?? "";
  // Configured when we can authenticate: a static token, OR username + password
  // (Tidal signs in with credentials and mints an 8h bearer token).
  if (!url || (!apiKey && !(username && password))) return null;
  return {
    url: url.replace(/\/+$/, ""),
    username,
    password,
    apiKey,
    assetsPath: process.env.TIDAL_ASSETS_PATH ?? "/api/v1/servers",
  };
}

// Cached bearer token (Tidal tokens live 8h). Refreshed before expiry; falls
// back to a full credential login when there's no valid refresh token.
let tidalToken: { access: string; refresh: string; exp: number } | null = null;

async function tidalBearer(config: TidalConfig): Promise<string> {
  if (config.apiKey) return config.apiKey;
  const now = Date.now();
  if (tidalToken && tidalToken.exp > now + 60_000) return tidalToken.access;

  const jsonHeaders = { "Content-Type": "application/json", Accept: "application/json" };

  if (tidalToken?.refresh) {
    try {
      const r = await fetch(`${config.url}/api/v1/refresh`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ refresh_token: tidalToken.refresh }),
        cache: "no-store",
      });
      if (r.ok) {
        const j: any = await r.json();
        if (j?.access_token) {
          tidalToken = {
            access: j.access_token,
            refresh: tidalToken.refresh,
            exp: now + Number(j.expires_in ?? 28800) * 1000,
          };
          return tidalToken.access;
        }
      }
    } catch {
      // fall through to a full sign-in
    }
  }

  const res = await fetch(`${config.url}/api/v1/authenticate`, {
    method: "POST",
    headers: jsonHeaders,
    body: JSON.stringify({ username: config.username, password: config.password }),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(
      `Tidal sign-in failed: HTTP ${res.status} — check TIDAL_API_URL (your workspace subdomain), TIDAL_USERNAME, and TIDAL_PASSWORD.`,
    );
  }
  const j: any = await res.json();
  if (!j?.access_token) throw new Error("Tidal sign-in returned no access token.");
  tidalToken = {
    access: j.access_token,
    refresh: j.refresh_token ?? "",
    exp: now + Number(j.expires_in ?? 28800) * 1000,
  };
  return tidalToken.access;
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

  const token = await tidalBearer(config);
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    "Content-Type": "application/json",
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
