import type { AssetCriticality, AssetExposure } from "@/lib/types";

// Tidal.io asset-inventory adapter — LIVE login + pull.
//
// Tidal.io (app.portal.tidal.io) is a Next.js SPA backed by a Laravel API at
// https://api.live.portal.tidal.io using Sanctum cookie auth. There is no
// API-key path; the browser signs in with email + password. We replicate that
// exact flow server-side:
//   1. GET  /auth/csrf-cookie        -> sets the XSRF-TOKEN + session cookies
//   2. POST /auth/login {email,pass} -> with the X-XSRF-TOKEN header, upgrades
//                                       the session cookie to an authenticated one
//   3. GET  /api/v1/warehouses/inventory (cookie jar) -> the live inventory
//
// Configure with:
//   TIDAL_EMAIL      the portal login email (e.g. chuck.helstein@gmi.com)
//   TIDAL_PASSWORD   the portal password
//   TIDAL_API_URL    override API base (default https://api.live.portal.tidal.io)
//   TIDAL_ORIGIN     override the SPA origin sent as Origin/Referer
//                    (default https://app.portal.tidal.io)

const DEFAULT_API = "https://api.live.portal.tidal.io";
const DEFAULT_ORIGIN = "https://app.portal.tidal.io";

export type TidalConfig = {
  url: string;
  origin: string;
  email: string;
  password: string;
};

export function tidalConfig(): TidalConfig | null {
  const email = process.env.TIDAL_EMAIL ?? process.env.TIDAL_USERNAME ?? "";
  const password = process.env.TIDAL_PASSWORD ?? "";
  if (!email || !password) return null;
  return {
    url: (process.env.TIDAL_API_URL ?? DEFAULT_API).replace(/\/+$/, ""),
    origin: (process.env.TIDAL_ORIGIN ?? DEFAULT_ORIGIN).replace(/\/+$/, ""),
    email,
    password,
  };
}

// --- cookie jar -------------------------------------------------------------
// Minimal cookie jar: accumulate Set-Cookie name=value pairs across the auth
// handshake and replay them on subsequent requests.
type Jar = Map<string, string>;

function absorb(jar: Jar, res: Response): void {
  // undici (Node 18.14+) exposes getSetCookie(); fall back to the combined header.
  const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[] };
  const raw: string[] =
    typeof anyHeaders.getSetCookie === "function"
      ? anyHeaders.getSetCookie()
      : res.headers.get("set-cookie")
        ? [res.headers.get("set-cookie") as string]
        : [];
  for (const line of raw) {
    const pair = line.split(";", 1)[0];
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name) jar.set(name, value);
  }
}

function cookieHeader(jar: Jar): string {
  return Array.from(jar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

function xsrf(jar: Jar): string {
  const raw = jar.get("XSRF-TOKEN") ?? "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// Sign in and return an authenticated cookie jar. Mirrors the SPA: hit the
// CSRF endpoint, then POST credentials with the X-XSRF-TOKEN header.
async function tidalLogin(config: TidalConfig): Promise<Jar> {
  const jar: Jar = new Map();
  const base = config.url;
  const common = {
    Accept: "application/json",
    Origin: config.origin,
    Referer: `${config.origin}/`,
  };

  const csrf = await fetch(`${base}/auth/csrf-cookie`, {
    headers: common,
    cache: "no-store",
  });
  absorb(jar, csrf);
  if (!jar.has("XSRF-TOKEN")) {
    throw new Error(
      `Tidal CSRF handshake failed (HTTP ${csrf.status}). Check TIDAL_API_URL.`,
    );
  }

  const login = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: {
      ...common,
      "Content-Type": "application/json",
      "X-XSRF-TOKEN": xsrf(jar),
      Cookie: cookieHeader(jar),
    },
    body: JSON.stringify({ email: config.email, password: config.password }),
    cache: "no-store",
  });
  absorb(jar, login);
  if (login.status === 419) {
    throw new Error("Tidal login rejected the CSRF token (HTTP 419).");
  }
  if (login.status === 401 || login.status === 422) {
    throw new Error("Tidal login failed — check TIDAL_EMAIL / TIDAL_PASSWORD.");
  }
  if (!login.ok) {
    throw new Error(`Tidal login failed: HTTP ${login.status}.`);
  }
  return jar;
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

function nameOf(v: unknown): string {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return String(o.name ?? o.title ?? o.label ?? o.value ?? "");
  }
  return String(v);
}

const s = (v: unknown): string => nameOf(v).trim();

function joinNonEmpty(parts: unknown[], sep = " "): string {
  return parts.map((p) => s(p)).filter(Boolean).join(sep);
}

// The scannable inventory lives under the MDM/network integrations (Intune,
// Auvik, SOTI), each with its own device schema. These map every source onto
// the shared TidalAsset shape. Devices are GMI-managed, so they attach to the
// internal "GMI" company unless a source carries a clearer site/tenant.

// Intune (Microsoft Endpoint Manager): managed endpoints, no IP (agent-based).
function normIntune(raw: any): TidalAsset {
  return {
    externalId: s(raw?.device_id) || s(raw?.serial_number) || s(raw?.azure_ad_device_id),
    hostname: s(raw?.device_name) || s(raw?.managed_device_name),
    ipAddresses: [],
    os: joinNonEmpty([raw?.operating_system, raw?.os_version]),
    owner:
      s(raw?.user_display_name) || s(raw?.user_principal_name) || s(raw?.email_address),
    customer: "GMI",
    tags: [s(raw?.management_agent), s(raw?.compliance_state), s(raw?.device_category_display_name)].filter(
      (t) => t && t !== "Unknown",
    ),
    criticality: mapCriticality(raw?.device_category_display_name),
    exposure: "Internal",
  };
}

// Auvik: network devices (switches, APs, AV, firewalls) — carry real IPs.
function normAuvik(raw: any): TidalAsset {
  const ips = ([] as unknown[])
    .concat(raw?.ip_addresses ?? [])
    .flat()
    .map((x) => s(x))
    .filter(Boolean);
  return {
    externalId: s(raw?.device_id) || s(raw?.serial_number),
    hostname: s(raw?.device_name) || ips[0] || "",
    ipAddresses: ips,
    os: joinNonEmpty([raw?.make_model, raw?.firmware_version]) || s(raw?.device_type),
    owner: "",
    customer: "GMI",
    tags: [s(raw?.device_type), s(raw?.vendor_name), s(raw?.online_status)].filter(Boolean),
    criticality: mapCriticality(raw?.device_type),
    exposure: mapExposure(raw?.device_type),
  };
}

// SOTI: rugged / mobile devices, nested identity/hardware/os/network blocks.
function normSoti(raw: any): TidalAsset {
  const ip = s(raw?.network?.ip_address);
  return {
    externalId: s(raw?.identity?.device_id) || s(raw?.hardware?.serial_number),
    hostname: s(raw?.identity?.device_name) || ip,
    ipAddresses: ip ? [ip] : [],
    os: joinNonEmpty([raw?.identity?.platform, raw?.os?.version]),
    owner: "",
    customer: s(raw?.identity?.path) || "GMI",
    tags: [s(raw?.identity?.platform), s(raw?.hardware?.model), s(raw?.identity?.mode)].filter(
      Boolean,
    ),
    criticality: "Normal",
    exposure: "Internal",
  };
}

type DeviceSource = { path: string; norm: (raw: any) => TidalAsset };

const DEVICE_SOURCES: DeviceSource[] = [
  { path: "/api/v1/integrations/intune/devices", norm: normIntune },
  { path: "/api/v1/integrations/auvik/devices", norm: normAuvik },
  { path: "/api/v1/integrations/soti/devices", norm: normSoti },
];

// Pull one paginated device source. Tidal returns { data, pagination:{ total,
// has_next, links:{ next } } } and uses cursor URLs for `next`. A source that
// isn't enabled (403/404) yields nothing rather than failing the whole sync.
async function pullDevices(
  config: TidalConfig,
  headers: Record<string, string>,
  source: DeviceSource,
): Promise<TidalAsset[]> {
  const out: TidalAsset[] = [];
  let url: string | null = `${config.url}${source.path}?per_page=100`;
  let guard = 0;
  while (url && guard < 200) {
    guard += 1;
    const res: Response = await fetch(url, { headers, cache: "no-store" });
    if (res.status === 403 || res.status === 404) return out;
    if (!res.ok) {
      throw new Error(
        `Tidal ${source.path} ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const data: any = await res.json();
    const rows: any[] = Array.isArray(data) ? data : data?.data ?? [];
    for (const r of rows) out.push(source.norm(r));

    const pg = data?.pagination;
    const next = pg?.links?.next;
    url = pg?.has_next && next ? String(next) : null;
  }
  return out;
}

// Log in, then pull every device source and merge into one asset list. Keeps
// only records that have something scannable (a hostname or an IP).
export async function tidalListAssets(): Promise<TidalAsset[]> {
  const config = tidalConfig();
  if (!config) throw new Error("Tidal is not configured. Set TIDAL_EMAIL and TIDAL_PASSWORD.");

  const jar = await tidalLogin(config);
  const headers = {
    Accept: "application/json",
    Origin: config.origin,
    Referer: `${config.origin}/`,
    Cookie: cookieHeader(jar),
  };

  const assets: TidalAsset[] = [];
  const errors: string[] = [];
  for (const source of DEVICE_SOURCES) {
    try {
      assets.push(...(await pullDevices(config, headers, source)));
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }

  const scannable = assets.filter((a) => a.hostname || a.ipAddresses.length);
  // Only surface an error if we got nothing at all and something went wrong.
  if (scannable.length === 0 && errors.length) throw new Error(errors[0]);
  return scannable;
}

// --- CSV import (offline fallback) -----------------------------------------
// If someone would rather export the inventory to CSV than store credentials,
// the portal's export is parsed here with fuzzy header matching so columns like
// "Business Criticality" / "Host Name" / "Customer" map regardless of casing.

function normKey(k: string): string {
  return k.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function parseCsvRows(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let cur: string[] = [];
  let field = "";
  let q = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (q) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else q = false;
      } else field += ch;
    } else if (ch === '"') q = true;
    else if (ch === ",") {
      cur.push(field);
      field = "";
    } else if (ch === "\n") {
      cur.push(field);
      rows.push(cur);
      cur = [];
      field = "";
    } else if (ch !== "\r") field += ch;
  }
  if (field !== "" || cur.length) {
    cur.push(field);
    rows.push(cur);
  }
  if (rows.length === 0) return [];
  const headers = rows[0].map(normKey);
  return rows
    .slice(1)
    .filter((r) => r.some((c) => c.trim() !== ""))
    .map((r) => {
      const o: Record<string, string> = {};
      headers.forEach((h, i) => {
        if (h) o[h] = (r[i] ?? "").trim();
      });
      return o;
    });
}

function pick(row: Record<string, string>, ...keys: string[]): string {
  for (const k of keys) {
    const v = row[k];
    if (v) return v;
  }
  return "";
}

export function parseTidalCsv(text: string): TidalAsset[] {
  return parseCsvRows(text).map((row) => {
    const ipRaw = pick(row, "ipaddress", "ipaddresses", "ip", "ips", "address", "ipv4");
    return {
      externalId: pick(row, "id", "assetid", "uuid", "instanceid", "serialnumber"),
      hostname: pick(row, "hostname", "host", "fqdn", "servername", "devicename", "name", "server"),
      ipAddresses: ipRaw.split(/[;,\s]+/).map((x) => x.trim()).filter(Boolean),
      os: pick(row, "os", "operatingsystem", "platform", "model"),
      owner: pick(row, "owner", "ownername", "assignedto", "assigneduser", "contact", "custodian"),
      customer: pick(row, "customer", "customername", "account", "organization", "org", "client", "company", "tenant", "site"),
      tags: pick(row, "tags", "labels").split(/[;,]+/).map((x) => x.trim()).filter(Boolean),
      criticality: mapCriticality(pick(row, "criticality", "businesscriticality", "importance", "tier", "priority")),
      exposure: mapExposure(pick(row, "environment", "exposure", "networkzone", "zone", "facing", "location")),
    };
  });
}
