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
  if (/(isolated|air.?gap|\bot\b|scada|segmented)/.test(v)) return "Isolated";
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
// the shared TidalAsset shape.
//
// CUSTOMER SEGMENTATION (governance-critical — no cross-tenant bleed):
// Tidal separates customers by which tenant/folder a device comes from, NOT by
// a per-device customer field. So each source is attributed by its own tenant
// boundary, and every distinct boundary becomes its own Vuln company:
//   Intune -> the user's email domain   (e.g. gmi.com  -> "GMI")
//   Auvik  -> the Auvik tenant name     (tenant_id -> display_name, e.g. "Ahwatukee")
//   SOTI   -> the top-level device path (identity.path root, e.g. "Bothell")
// Anything that can't be attributed is quarantined in a clearly-labelled
// "Tidal Unmapped (<source>)" bucket — it is NEVER folded into a real customer.
// Each asset also carries provenance tags (src:*, tenant:*/domain:*/path:*) so
// the customer attribution is auditable.

// CUSTOMER SEGMENTATION (governance-critical — authoritative, no bleed):
// Tidal is a multi-company MSP portal (GMI + ~49 client companies) and its
// integrations (Intune/Auvik/SOTI) are connected PER CLIENT COMPANY. So the
// customer is the Tidal client company itself: we enumerate companies, switch
// the session into each one, and pull whatever devices that company exposes —
// attributing every device to that company. A device can therefore never be
// credited to the wrong customer. Location signals (Auvik tenant, SOTI path)
// are kept only as `site:` tags, not as the customer.

// Per-company context for the normalizers: the owning company name (the
// customer) plus that company's Auvik tenant_id -> display_name map (for site
// tags).
type NormCtx = { companyName: string; auvikTenants: Map<string, string> };

// Top-level segment of a SOTI device path ("Bothell/Staging" -> "Bothell").
function firstPathSegment(path: string): string {
  return path.split(/[\\/]+/).map((x) => x.trim()).filter(Boolean)[0] ?? "";
}

// Intune (Microsoft Endpoint Manager): managed endpoints, no IP (agent-based).
function normIntune(raw: any, ctx: NormCtx): TidalAsset {
  const email = s(raw?.user_principal_name) || s(raw?.email_address);
  const domain = email.includes("@") ? email.split("@").pop() ?? "" : "";
  return {
    externalId: `intune:${s(raw?.device_id) || s(raw?.serial_number) || s(raw?.azure_ad_device_id)}`,
    hostname: s(raw?.device_name) || s(raw?.managed_device_name),
    ipAddresses: [],
    os: joinNonEmpty([raw?.operating_system, raw?.os_version]),
    owner:
      s(raw?.user_display_name) || s(raw?.user_principal_name) || s(raw?.email_address),
    customer: ctx.companyName,
    tags: ["tidal", "src:intune", domain ? `domain:${domain}` : "", s(raw?.compliance_state)].filter(
      (t) => t && t !== "Unknown",
    ),
    criticality: mapCriticality(raw?.device_category_display_name),
    exposure: "Internal",
  };
}

// Auvik: network devices (switches, APs, AV, firewalls) — carry real IPs.
function normAuvik(raw: any, ctx: NormCtx): TidalAsset {
  const ips = ([] as unknown[])
    .concat(raw?.ip_addresses ?? [])
    .flat()
    .map((x) => s(x))
    .filter(Boolean);
  const tenantId = s(raw?.tenant_id);
  const site = ctx.auvikTenants.get(tenantId) || s(raw?.tenant_domain_prefix);
  return {
    externalId: `auvik:${s(raw?.device_id) || s(raw?.serial_number)}`,
    hostname: s(raw?.device_name) || ips[0] || "",
    ipAddresses: ips,
    os: joinNonEmpty([raw?.make_model, raw?.firmware_version]) || s(raw?.device_type),
    owner: "",
    customer: ctx.companyName,
    tags: [
      "tidal",
      "src:auvik",
      site ? `site:${site}` : "",
      s(raw?.device_type),
      s(raw?.vendor_name),
    ].filter(Boolean),
    criticality: mapCriticality(raw?.device_type),
    exposure: mapExposure(raw?.device_type),
  };
}

// SOTI: rugged / mobile devices, nested identity/hardware/os/network blocks.
function normSoti(raw: any, _ctx: NormCtx): TidalAsset {
  const ip = s(raw?.network?.ip_address);
  const path = s(raw?.identity?.path);
  const site = firstPathSegment(path);
  return {
    externalId: `soti:${s(raw?.identity?.device_id) || s(raw?.hardware?.serial_number)}`,
    hostname: s(raw?.identity?.device_name) || ip,
    ipAddresses: ip ? [ip] : [],
    os: joinNonEmpty([raw?.identity?.platform, raw?.os?.version]),
    owner: "",
    customer: _ctx.companyName,
    tags: ["tidal", "src:soti", site ? `site:${site}` : "", s(raw?.hardware?.model)].filter(
      Boolean,
    ),
    criticality: "Normal",
    exposure: "Internal",
  };
}

type DeviceSource = { path: string; norm: (raw: any, ctx: NormCtx) => TidalAsset };

const DEVICE_SOURCES: DeviceSource[] = [
  { path: "/api/v1/integrations/intune/devices", norm: normIntune },
  { path: "/api/v1/integrations/auvik/devices", norm: normAuvik },
  { path: "/api/v1/integrations/soti/devices", norm: normSoti },
];

type TidalCompany = { id: string; name: string; type: string };

// Tidal's pagination `next` links come back as http:// (not https), which drops
// the secure session cookie and breaks the follow-up request. Rebuild every
// next URL against the configured https base so the scheme/host are correct.
function rehost(config: TidalConfig, raw: string): string {
  try {
    const u = new URL(raw);
    return `${config.url}${u.pathname}${u.search}`;
  } catch {
    return raw.startsWith("/") ? `${config.url}${raw}` : raw;
  }
}

// Build request headers carrying the jar's current cookies (which rotate as the
// session switches companies).
function jarHeaders(config: TidalConfig, jar: Jar): Record<string, string> {
  return {
    Accept: "application/json",
    Origin: config.origin,
    Referer: `${config.origin}/`,
    Cookie: cookieHeader(jar),
  };
}

// The full client roster (GMI + affiliates + clients). Each is a customer.
async function listCompanies(config: TidalConfig, jar: Jar): Promise<TidalCompany[]> {
  const companies: TidalCompany[] = [];
  let url: string | null = `${config.url}/api/v1/admin/companies?per_page=100`;
  let guard = 0;
  while (url && guard < 50) {
    guard += 1;
    const res: Response = await fetch(url, { headers: jarHeaders(config, jar), cache: "no-store" });
    absorb(jar, res);
    if (!res.ok) break;
    const data: any = await res.json();
    const rows: any[] = Array.isArray(data) ? data : data?.data ?? [];
    for (const r of rows) {
      const id = s(r?.id);
      const name = s(r?.name);
      if (id && name) companies.push({ id, name, type: s(r?.type) });
    }
    const pg = data?.pagination;
    url = pg?.has_next && pg?.links?.next ? rehost(config, String(pg.links.next)) : null;
  }
  return companies;
}

// Point the session at a given company. State-changing, so it carries the XSRF
// header; the response cookies are absorbed so the jar stays valid. Throws on
// a non-2xx response — if the switch fails the session is still parked on the
// PREVIOUS company, and pulling devices would attribute them to the wrong
// customer, so the caller must skip this company entirely.
async function switchCompany(config: TidalConfig, jar: Jar, companyId: string): Promise<void> {
  const res = await fetch(`${config.url}/api/v1/admin/companies/switch-company`, {
    method: "POST",
    headers: {
      ...jarHeaders(config, jar),
      "Content-Type": "application/json",
      "X-XSRF-TOKEN": xsrf(jar),
    },
    body: JSON.stringify({ company_id: companyId }),
    cache: "no-store",
  });
  absorb(jar, res);
  if (!res.ok) {
    throw new Error(
      `Tidal switch-company failed (HTTP ${res.status}) — skipping this company to avoid cross-customer attribution.`,
    );
  }
}

// Best-effort Auvik tenant_id -> display_name for the CURRENT company context.
async function fetchAuvikTenants(config: TidalConfig, jar: Jar): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  try {
    const res = await fetch(`${config.url}/api/v1/integrations/auvik/tenants`, {
      headers: jarHeaders(config, jar),
      cache: "no-store",
    });
    absorb(jar, res);
    if (!res.ok) return map;
    const data: any = await res.json();
    const rows: any[] = Array.isArray(data) ? data : data?.data ?? [];
    for (const t of rows) {
      const id = s(t?.id);
      const name = s(t?.display_name) || s(t?.name);
      if (id && name) map.set(id, name);
    }
  } catch {
    // best-effort
  }
  return map;
}

// Pull one paginated device source in the CURRENT company context. Tidal
// returns { data, pagination:{ has_next, links:{ next } } } with cursor URLs.
// A company without that integration answers 400/403/404 — treated as "no
// devices here", not an error.
async function pullDevices(
  config: TidalConfig,
  jar: Jar,
  source: DeviceSource,
  ctx: NormCtx,
): Promise<TidalAsset[]> {
  const out: TidalAsset[] = [];
  let url: string | null = `${config.url}${source.path}?per_page=100`;
  let guard = 0;
  while (url && guard < 200) {
    guard += 1;
    const res: Response = await fetch(url, { headers: jarHeaders(config, jar), cache: "no-store" });
    absorb(jar, res);
    if (res.status === 400 || res.status === 403 || res.status === 404) return out;
    if (!res.ok) {
      throw new Error(
        `Tidal ${source.path} ${res.status}: ${await res.text().catch(() => res.statusText)}`,
      );
    }
    const data: any = await res.json();
    const rows: any[] = Array.isArray(data) ? data : data?.data ?? [];
    for (const r of rows) out.push(source.norm(r, ctx));

    // Two pagination shapes: Intune is cursor-based (has_next + links.next);
    // Auvik/SOTI are page-based (current_page/last_page, no has_next). Follow
    // links.next unless we're explicitly at the end of either scheme.
    const pg = data?.pagination;
    const next = pg?.links?.next;
    let more = false;
    if (next) {
      if (pg.has_next === true) more = true; // cursor
      else if (pg.has_next === undefined) {
        // page-based: continue while there are pages left
        more = pg.last_page == null || Number(pg.current_page) < Number(pg.last_page);
      }
    }
    url = more ? rehost(config, String(next)) : null;
  }
  return out;
}

// Progress updates emitted during a sync so a long run can drive a UI.
export type TidalProgress = {
  phase?: string;
  companiesTotal?: number;
  companiesDone?: number;
  currentCompany?: string;
  assetsFound?: number;
};

// Log in, enumerate every client company, and pull each one's devices in its
// own session context. Every asset is attributed to the company it was pulled
// under — the authoritative customer boundary, so there is no cross-customer
// bleed. Keeps only records with something scannable (a hostname or an IP).
// onProgress (optional) is invoked as each company is processed.
export async function tidalListAssets(
  onProgress?: (p: TidalProgress) => void,
): Promise<TidalAsset[]> {
  const config = tidalConfig();
  if (!config) throw new Error("Tidal is not configured. Set TIDAL_EMAIL and TIDAL_PASSWORD.");

  onProgress?.({ phase: "Signing in" });
  const jar = await tidalLogin(config);
  onProgress?.({ phase: "Enumerating companies" });
  const companies = await listCompanies(config, jar);
  if (companies.length === 0) {
    throw new Error("Tidal returned no companies for this account.");
  }
  onProgress?.({ companiesTotal: companies.length, companiesDone: 0 });

  const assets: TidalAsset[] = [];
  const errors: string[] = [];
  let done = 0;
  for (const company of companies) {
    onProgress?.({
      phase: `Pulling ${company.name}`,
      currentCompany: company.name,
      companiesDone: done,
    });
    try {
      await switchCompany(config, jar, company.id);
      const ctx: NormCtx = {
        companyName: company.name,
        auvikTenants: await fetchAuvikTenants(config, jar),
      };
      for (const source of DEVICE_SOURCES) {
        try {
          assets.push(...(await pullDevices(config, jar, source, ctx)));
        } catch (err) {
          errors.push(`${company.name}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    } catch (err) {
      errors.push(`${company.name}: ${err instanceof Error ? err.message : String(err)}`);
    }
    done += 1;
    onProgress?.({ companiesDone: done, assetsFound: assets.length });
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
