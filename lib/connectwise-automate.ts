import type { AssetCriticality, AssetExposure } from "@/lib/types";

// ConnectWise Automate (RMM) adapter — direct against Automate's own REST
// API, bypassing Tidal entirely. Tidal has a live "SD Devices > AUTOMATE"
// integration per client company, but lib/tidal.ts's DEVICE_SOURCES never
// queried it (only Intune/Auvik/SOTI) -- that's why a customer whose real
// inventory lives in Automate (like Atlas Healthcare Partners, confirmed
// live: 1,161 devices) synced zero assets from Tidal. Automate's API is
// well-documented and already reachable with the existing MSP-wide
// integration credentials, so this talks to it directly instead of trying
// to reverse-engineer Tidal's wrapper.
//
// Verified live against https://gmi.hostedrmm.com/cwa/api/v1:
//   POST /apitoken {UserName,Password,TwoFactorPasscode} + header
//        ClientId:<api client id>  ->  {AccessToken, TokenType, ...}
//   GET  /clients?condition=...    ->  [{Id, Name, Company, ...}]
//   GET  /computers?condition=Client/Id=<id>&pagesize=N&page=N
//        -> [{Id, ComputerName, Client:{Id,Name}, OperatingSystemName,
//             OperatingSystemVersion, LocalIPAddress, Type, Status,
//             LastUserName, SerialNumber, ...}], Total-Count header.
//
// Configure with:
//   AUTOMATE_BASE_URL       e.g. https://gmi.hostedrmm.com/cwa/api/v1
//   AUTOMATE_API_CLIENT_ID  the API registration's ClientId header value
//                           (NOT an Automate "Client"/customer id)
//   AUTOMATE_USERNAME       Automate API user
//   AUTOMATE_PASSWORD       Automate API password

export type AutomateConfig = {
  baseUrl: string;
  apiClientId: string;
  username: string;
  password: string;
};

export function automateConfig(): AutomateConfig | null {
  const baseUrl = process.env.AUTOMATE_BASE_URL ?? "";
  const apiClientId = process.env.AUTOMATE_API_CLIENT_ID ?? "";
  const username = process.env.AUTOMATE_USERNAME ?? "";
  const password = process.env.AUTOMATE_PASSWORD ?? "";
  if (!baseUrl || !apiClientId || !username || !password) return null;
  return { baseUrl: baseUrl.replace(/\/+$/, ""), apiClientId, username, password };
}

async function automateToken(config: AutomateConfig): Promise<string> {
  const res = await fetch(`${config.baseUrl}/apitoken`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ClientId: config.apiClientId },
    body: JSON.stringify({
      UserName: config.username,
      Password: config.password,
      TwoFactorPasscode: "",
    }),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(
      `Automate auth failed (HTTP ${res.status}): ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const j: any = await res.json();
  if (!j?.AccessToken) throw new Error("Automate auth response had no AccessToken.");
  return j.AccessToken as string;
}

function authHeaders(config: AutomateConfig, token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, ClientId: config.apiClientId, Accept: "application/json" };
}

const PAGE = 250;
// Automate's own client roster (and some clients' device counts) can run
// into the thousands; this is a sanity ceiling against a runaway loop, not
// an expected limit.
const MAX_PAGES = 200;

export type AutomateClient = { id: string; name: string };

// The full "Client" roster (Automate's own term for its MSP customers —
// unrelated to the `apiClientId` API-registration header above).
export async function automateListClients(config: AutomateConfig): Promise<AutomateClient[]> {
  const token = await automateToken(config);
  const headers = authHeaders(config, token);
  const out: AutomateClient[] = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const res = await fetch(`${config.baseUrl}/clients?pagesize=${PAGE}&page=${page}`, {
      headers,
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(
        `Automate clients ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const rows: any[] = await res.json();
    if (!Array.isArray(rows) || rows.length === 0) break;
    for (const r of rows) {
      const id = String(r?.Id ?? "").trim();
      const name = String(r?.Name ?? r?.Company ?? "").trim();
      if (id && name) out.push({ id, name });
    }
    if (rows.length < PAGE) break;
  }
  return out;
}

export type AutomateAsset = {
  externalId: string;
  hostname: string;
  ipAddresses: string[];
  os: string;
  owner: string;
  tags: string[];
  criticality: AssetCriticality;
  exposure: AssetExposure;
};

function mapCriticality(type: string): AssetCriticality {
  return /server/i.test(type) ? "High" : "Normal";
}

function normalizeComputer(raw: any): AutomateAsset {
  const type = String(raw?.Type ?? "");
  const loggedIn = Array.isArray(raw?.LoggedInUsers) ? raw.LoggedInUsers[0]?.LoggedInUserName : undefined;
  const owner = String(raw?.LastUserName ?? loggedIn ?? "").replace(/^[^\\]*\\/, "");
  const ip = String(raw?.LocalIPAddress ?? "").trim();
  return {
    // Only emit a prefixed id when Id is actually present -- `automate:${""}`
    // would still be a non-empty, truthy externalId, so every record missing
    // Id would collide on it and silently overwrite each other via
    // upsertAsset's dedup match (same bug class as Tidal's/CrowdStrike's
    // equivalent fallbacks, just fixed).
    externalId: raw?.Id != null ? `automate:${raw.Id}` : "",
    hostname: String(raw?.ComputerName ?? "").trim(),
    ipAddresses: ip ? [ip] : [],
    os: [raw?.OperatingSystemName, raw?.OperatingSystemVersion].filter(Boolean).join(" ").trim(),
    owner,
    tags: ["automate", type ? `type:${type}` : "", raw?.Status ? `status:${raw.Status}` : ""].filter(
      Boolean,
    ),
    criticality: mapCriticality(type),
    exposure: "Internal",
  };
}

// Automate's REST API filters via a SQL-like `condition` query param;
// "Client/Id=<n>" scopes computers to one customer (verified live: Atlas's
// Client Id 98 returns exactly the 1,161-device count visible in the
// portal's own Automate Devices view).
export async function automateListComputers(
  config: AutomateConfig,
  clientId: string,
): Promise<AutomateAsset[]> {
  const token = await automateToken(config);
  const headers = authHeaders(config, token);
  const condition = encodeURIComponent(`Client/Id=${clientId}`);
  const out: AutomateAsset[] = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const res = await fetch(
      `${config.baseUrl}/computers?pagesize=${PAGE}&page=${page}&condition=${condition}`,
      { headers, cache: "no-store" },
    );
    if (!res.ok) {
      throw new Error(
        `Automate computers ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const rows: any[] = await res.json();
    if (!Array.isArray(rows) || rows.length === 0) break;
    out.push(...rows.map(normalizeComputer).filter((a) => a.hostname));
    if (rows.length < PAGE) break;
  }
  return out;
}
