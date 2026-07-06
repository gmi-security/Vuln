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
  inventoryPath: string;
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
    inventoryPath: process.env.TIDAL_INVENTORY_PATH ?? "/api/v1/warehouses/inventory",
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

// Best-effort normalizer over a Tidal warehouse-inventory record. Warehouse
// items nest company/site/category as objects and carry device fields (name,
// serial, model, assigned user), so we read both flat and nested shapes.
export function normalizeTidalAsset(raw: any): TidalAsset {
  const ips: string[] = ([] as unknown[])
    .concat(
      raw?.ip_addresses ??
        raw?.ipAddresses ??
        raw?.ips ??
        raw?.ip_address ??
        raw?.ip ??
        [],
    )
    .flat()
    .map((x) => nameOf(x))
    .filter(Boolean);

  return {
    externalId: String(raw?.id ?? raw?.asset_id ?? raw?.uuid ?? raw?.serial_number ?? ""),
    hostname: String(
      raw?.hostname ??
        raw?.name ??
        raw?.fqdn ??
        raw?.host ??
        raw?.device_name ??
        raw?.asset_tag ??
        "",
    ),
    ipAddresses: ips,
    os: String(
      nameOf(raw?.os) ||
        nameOf(raw?.operating_system) ||
        nameOf(raw?.platform) ||
        nameOf(raw?.model) ||
        "",
    ),
    owner: String(
      nameOf(raw?.owner) ||
        nameOf(raw?.owner_name) ||
        nameOf(raw?.assigned_to) ||
        nameOf(raw?.assigned_user) ||
        nameOf(raw?.user) ||
        "",
    ),
    customer: String(
      nameOf(raw?.customer) ||
        nameOf(raw?.customer_name) ||
        nameOf(raw?.company) ||
        nameOf(raw?.account) ||
        nameOf(raw?.organization) ||
        nameOf(raw?.org) ||
        nameOf(raw?.site) ||
        "",
    ),
    tags: ([] as unknown[])
      .concat(raw?.tags ?? raw?.labels ?? [])
      .flat()
      .map((x) => nameOf(x))
      .filter(Boolean),
    criticality: mapCriticality(
      raw?.criticality ?? raw?.business_criticality ?? raw?.importance ?? raw?.tier,
    ),
    exposure: mapExposure(
      raw?.exposure ?? raw?.environment ?? raw?.network_zone ?? raw?.zone ?? raw?.facing,
    ),
  };
}

// Log in and pull the full asset inventory. Paginates on Laravel-style
// meta/links or offset when present; returns normalized assets.
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
  const sep = config.inventoryPath.includes("?") ? "&" : "?";
  let url: string | null = `${config.url}${config.inventoryPath}${sep}per_page=200`;
  let guard = 0;
  while (url && guard < 100) {
    guard += 1;
    const res: Response = await fetch(url, { headers, cache: "no-store" });
    if (!res.ok) {
      throw new Error(`Tidal ${res.status}: ${await res.text().catch(() => res.statusText)}`);
    }
    const data: any = await res.json();
    const records: any[] = Array.isArray(data)
      ? data
      : data?.data ?? data?.assets ?? data?.results ?? data?.items ?? data?.inventory ?? [];
    for (const r of records) assets.push(normalizeTidalAsset(r));

    const next =
      data?.links?.next ?? data?.next_page_url ?? data?.next ?? data?.meta?.next ?? null;
    url = next ? (String(next).startsWith("http") ? String(next) : `${config.url}${next}`) : null;
  }
  return assets;
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
