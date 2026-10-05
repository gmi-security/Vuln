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

// A CrowdStrike Falcon tenant to sync, plus which company its devices and
// findings attach to. `customerName` is optional only for the first
// (unsuffixed) tenant — omitted, it falls back to the internal GMI org, the
// same "own-estate" default this connector has always had. Every additional
// tenant (an MSSP client with their own separate CrowdStrike CID, distinct
// from GMI's own) requires a customer name: there can only be one unnamed
// "default" tenant.
export type FalconTenant = FalconConfig & { customerName?: string; label: string };

// Reads the base (unsuffixed) tenant plus any FALCON_CLIENT_ID_2,
// FALCON_CLIENT_ID_3, ... tenants, each with its own FALCON_CLIENT_SECRET_N /
// FALCON_CLOUD_N / FALCON_CUSTOMER_N. Stops at the first missing numbered
// tenant, so gaps in the numbering aren't supported (keep them sequential).
export function falconConfigs(): FalconTenant[] {
  const tenants: FalconTenant[] = [];
  const base = falconConfig();
  if (base) {
    tenants.push({
      ...base,
      customerName: process.env.FALCON_CUSTOMER?.trim() || undefined,
      label: "primary",
    });
  }
  for (let n = 2; ; n++) {
    const clientId = process.env[`FALCON_CLIENT_ID_${n}`];
    const clientSecret = process.env[`FALCON_CLIENT_SECRET_${n}`];
    if (!clientId || !clientSecret) break;
    const customerName = process.env[`FALCON_CUSTOMER_${n}`]?.trim();
    if (!customerName) {
      console.error(
        `[crowdstrike] FALCON_CLIENT_ID_${n} is set without FALCON_CUSTOMER_${n} — skipping tenant ${n} (every additional tenant must be pinned to a named client company).`,
      );
      continue;
    }
    const cloud = (process.env[`FALCON_CLOUD_${n}`] ?? "us-1").toLowerCase();
    tenants.push({
      clientId,
      clientSecret,
      baseUrl: CLOUD_HOSTS[cloud] ?? "https://api.crowdstrike.com",
      customerName,
      label: customerName,
    });
  }
  return tenants;
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

// Wraps fetch with a hard timeout. Node's native fetch has no default timeout
// so CrowdStrike API stalls would hang background tasks indefinitely.
function timedFetchOnce(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  return fetch(url, { ...init, signal: ac.signal }).finally(() => clearTimeout(timer));
}

// A large tenant's device/vuln hydration fans out many of these requests
// (bounded by runWithConcurrency below), which makes hitting CrowdStrike's
// rate limiter an expected, recoverable event rather than a rare one — retry
// 429/500/502/503/504 with backoff (honoring Retry-After when CrowdStrike sends
// it) instead of failing the whole sync over a single throttled request.
async function timedFetch(url: string, init: RequestInit, timeoutMs = 60_000): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await timedFetchOnce(url, init, timeoutMs);
    } catch (error) {
      if ((init.method ?? "GET").toUpperCase() !== "GET" ||
          !(error instanceof Error && error.name === "AbortError") || attempt >= 4) throw error;
      await new Promise(resolve => setTimeout(resolve, Math.min(500 * 2 ** attempt, 8_000)));
      continue;
    }
    if (res.ok || ![429, 500, 502, 503, 504].includes(res.status) || attempt >= 4) return res;
    const retryAfter = Number(res.headers.get("retry-after"));
    const delayMs = Number.isFinite(retryAfter) && retryAfter > 0
      ? Math.min(retryAfter * 1000, 30_000)
      : Math.min(500 * 2 ** attempt, 8_000);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

// Runs `fn` over `items` with at most `limit` in flight at once, so a large
// tenant's device/vuln hydration (which used to fire hundreds of requests in
// one unbounded Promise.all) can't overwhelm CrowdStrike's rate limiter just
// because the underlying dataset is large.
async function runWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker() {
    for (let i = next++; i < items.length; i = next++) results[i] = await fn(items[i]);
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

async function falconToken(config: FalconConfig, quick = false): Promise<string> {
  const res = await (quick ? timedFetchOnce : timedFetch)(
    `${config.baseUrl}/oauth2/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
      cache: "no-store",
    },
    quick ? 10_000 : 15_000,
  );
  if (!res.ok) {
    throw new Error(
      `Falcon auth failed: ${res.status} ${await res.text().catch(() => res.statusText)}`,
    );
  }
  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) throw new Error("Falcon auth returned no token.");
  return data.access_token;
}

// A diagnostic request must never walk the full device or Spotlight estate.
// Both query endpoints expose their total in pagination metadata, so one
// bounded request per source is enough to show whether data is available.
export async function falconProbeCounts(config: FalconConfig): Promise<{
  hostsAvailable: number | null;
  spotlightFindingsAvailable: number | null;
  hostsError: string | null;
  spotlightError: string | null;
}> {
  const token = await falconToken(config, true);
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  async function count(url: URL): Promise<number> {
    const response = await timedFetchOnce(url.toString(), { headers, cache: "no-store" }, 10_000);
    if (!response.ok) throw new Error(`Query returned HTTP ${response.status}`);
    const json = await response.json();
    const total = json?.meta?.pagination?.total;
    if (!Number.isSafeInteger(total) || total < 0) throw new Error("Query omitted a valid pagination total");
    return total;
  }
  const devicesUrl = new URL(`${config.baseUrl}/devices/queries/devices/v1`);
  devicesUrl.searchParams.set("limit", "1");
  const spotlightUrl = new URL(`${config.baseUrl}/spotlight/queries/vulnerabilities/v1`);
  spotlightUrl.searchParams.set("filter", "status:'open',status:'reopen'");
  spotlightUrl.searchParams.set("limit", "1");
  const [devices, spotlight] = await Promise.allSettled([count(devicesUrl), count(spotlightUrl)]);
  return {
    hostsAvailable: devices.status === "fulfilled" ? devices.value : null,
    spotlightFindingsAvailable: spotlight.status === "fulfilled" ? spotlight.value : null,
    hostsError: devices.status === "rejected" ? String(devices.reason) : null,
    spotlightError: spotlight.status === "rejected" ? String(spotlight.reason) : null,
  };
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
    // device_id only -- cid is the tenant's Customer ID, the SAME value for
    // every device in the tenant, not a per-device identifier. Falling back
    // to it would make every record missing device_id collide on externalId
    // and silently overwrite each other via upsertAsset's dedup match.
    externalId: String(raw?.device_id ?? ""),
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
  id: string;
  raw: unknown;
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

export type SpotlightListResult = { findings: SpotlightFinding[]; truncated: boolean };

// Synthesized for an ID the entities endpoint no longer returns -- CrowdStrike
// stops resolving an ID once the underlying finding is closed/remediated/
// removed, which routinely happens to some fraction of IDs discovered hours
// earlier on a multi-hour scan against a live, constantly-changing dataset.
// Recorded as closed rather than dropped, so the run's "every discovered ID
// has exactly one record" guarantee (enforced at promotion) still holds and
// the finding doesn't just silently vanish from the dataset.
function tombstoneSpotlightResource(id: string): SpotlightFinding {
  return {
    id, raw: { id, unresolved: true },
    cve: `CS-${id}`,
    hostname: "", localIp: "", externalIp: "", os: "",
    severity: "Medium", cvss: 0,
    title: "CrowdStrike Spotlight finding (no longer resolvable)",
    description: "CrowdStrike no longer returns details for this finding ID; it was likely closed or remediated after discovery.",
    remediation: "",
    exploitAvailable: false,
    status: "closed",
    exprRating: "",
  };
}

function parseSpotlightResource(config: FalconTenant, v: any): SpotlightFinding {
  const id = String(v?.id ?? "").trim();
  if (!id) throw new Error(`Spotlight source vulnerability ID is missing for ${config.label}.`);
  const cve = String(v?.cve?.id ?? "").toUpperCase() || `CS-${v?.id ?? "vuln"}`;
  const sev: Severity =
    EXPRT_SEV[String(v?.cve?.exprt_rating ?? v?.severity ?? "").toUpperCase()] ?? "Medium";
  const cvss = Number(v?.cve?.cvss_v3 ?? v?.cve?.cvss_v2 ?? 5.0);
  return {
    id, raw: v, cve,
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
}

// CrowdStrike's own error confirms the real ceiling for this endpoint:
// {"code":400,"message":"1000 is an invalid page size, must be between 1
// and 400"} -- 400 is not an arbitrary choice, it's the server-enforced
// max. Discovery is cursor-paginated (each page's "after" token is only
// known once the prior page's response arrives), so it's inherently a
// chain of sequential round-trips; a bigger page would cut how many
// round-trips a full walk needs, but 400 is as large as CrowdStrike will
// accept. Overridable without a redeploy (just an app restart) only to go
// *lower* if a specific tenant needs it; an out-of-range value falls back
// to 400.
const SPOTLIGHT_DISCOVERY_PAGE_SIZE = (() => {
  const raw = Number(process.env.SPOTLIGHT_DISCOVERY_PAGE_SIZE);
  return Number.isInteger(raw) && raw > 0 && raw <= 400 ? raw : 400;
})();

// Discovery and hydration are separate so a large import can persist the ID
// set before fetching full records and resume either phase independently.
export async function createSpotlightSession(config: FalconTenant) {
  let token = await falconToken(config);
  let renewal: Promise<string> | undefined;
  async function request(url: string): Promise<Response> {
    const usedToken = token;
    const get = (bearer: string) => timedFetch(url, {
      headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" }, cache: "no-store",
    });
    const response = await get(usedToken);
    if (response.status !== 401) return response;
    await response.body?.cancel().catch(() => {});
    if (token === usedToken) {
      renewal ??= falconToken(config)
        .then(nextToken => { token = nextToken; return nextToken; })
        .finally(() => { renewal = undefined; });
      await renewal;
    }
    return get(token);
  }
  async function queryPage(after = "", filter = "status:'open',status:'reopen'"): Promise<{ ids: string[]; next: string; total: number | null }> {
    const url = new URL(`${config.baseUrl}/spotlight/queries/vulnerabilities/v1`);
    url.searchParams.set("filter", filter);
    url.searchParams.set("limit", String(SPOTLIGHT_DISCOVERY_PAGE_SIZE));
    if (after) url.searchParams.set("after", after);
    const response = await request(url.toString());
    if (!response.ok) throw new Error(`Spotlight query ${response.status}: ${await response.text().catch(() => response.statusText)}`);
    const json: any = await response.json();
    if (!Array.isArray(json?.resources) || json.resources.some((id: unknown) => typeof id !== "string" || !id))
      throw new Error(`Spotlight query returned invalid IDs for ${config.label}.`);
    const next = json?.meta?.pagination?.after ?? "";
    if (typeof next !== "string") throw new Error(`Spotlight query returned an invalid cursor for ${config.label}.`);
    if (!json.resources.length && next) throw new Error(`Spotlight query returned an empty page with a cursor for ${config.label}.`);
    const rawTotal = json?.meta?.pagination?.total;
    return { ids: json.resources, next, total: Number.isSafeInteger(rawTotal) && rawTotal >= 0 ? rawTotal : null };
  }
  async function hydrateIds(ids: string[]): Promise<SpotlightFinding[]> {
    if (!ids.length) return [];
    const groups: string[][] = [];
    for (let i = 0; i < ids.length; i += 400) groups.push(ids.slice(i, i + 400));
    const results = await runWithConcurrency(groups, 8, async group => {
      const url = new URL(`${config.baseUrl}/spotlight/entities/vulnerabilities/v2`);
      for (const id of group) url.searchParams.append("ids", id);
      const response = await request(url.toString());
      if (!response.ok) throw new Error(`Spotlight entities ${response.status}: ${await response.text().catch(() => response.statusText)}`);
      const json: any = await response.json();
      if (!Array.isArray(json?.resources) || json.resources.length > group.length)
        throw new Error(`Spotlight entity hydration returned an invalid response for ${config.label}.`);
      const requested = new Set(group);
      const returnedIds = new Set<string>(json.resources.map((item: any) => String(item?.id ?? "").trim()));
      if (returnedIds.has("") || returnedIds.size !== json.resources.length || Array.from(returnedIds).some(id => !requested.has(id)))
        throw new Error(`Spotlight entity hydration IDs mismatch for ${config.label}.`);
      const findings = json.resources.map((item: any) => parseSpotlightResource(config, item));
      // A multi-hour scan walks a live, constantly-changing dataset -- an ID
      // discovered hours ago can legitimately stop resolving by the time
      // hydration reaches it. That's expected churn, not a broken response
      // (anything actually wrong with the response -- bad shape, duplicate
      // or unrequested IDs -- still throws above), so record it as closed
      // instead of failing the whole run.
      if (json.resources.length < group.length) {
        const missing = group.filter(id => !returnedIds.has(id));
        console.error(`[spotlight] ${missing.length} ID(s) for ${config.label} no longer resolvable, recording as closed: ${missing.join(",")}`);
        findings.push(...missing.map(tombstoneSpotlightResource));
      }
      return findings;
    });
    return results.flat();
  }
  return { queryPage, hydrateIds };
}

// Splitting "status:'open',status:'reopen'" into its two constituent values
// lets discovery walk both concurrently instead of one combined sequential
// cursor -- each value already appears standalone in that same OR'd filter,
// so this is a proven-valid split, not a guess at an unverified field (e.g.
// severity) this sandbox has no way to test against a live CrowdStrike
// instance. status is mutually exclusive and exhaustive over "open"/"reopen"
// (that IS the existing combined filter), so no record can land in both
// partitions or neither.
export const SPOTLIGHT_DISCOVERY_PARTITIONS: { key: string; filter: string }[] = [
  { key: "open", filter: "status:'open'" },
  { key: "reopen", filter: "status:'reopen'" },
];

// CrowdStrike Spotlight API: query open vuln ids and yield bounded hydrated
// batches. Requires scope: spotlight-vulnerabilities:read.
export async function* spotlightFindingBatches(config: FalconTenant): AsyncGenerator<SpotlightFinding[]> {
  let token = await falconToken(config);
  let renewal: Promise<string> | undefined;
  async function spotlightFetch(url: string): Promise<Response> {
    const usedToken = token;
    const request = (bearer: string) => timedFetch(url, {
      headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" }, cache: "no-store",
    });
    const response = await request(usedToken);
    if (response.status !== 401) return response;
    await response.body?.cancel().catch(() => {});
    if (token === usedToken) {
      renewal ??= falconToken(config)
        .then(nextToken => { token = nextToken; return nextToken; })
        .finally(() => { renewal = undefined; });
      await renewal;
    }
    return request(token);
  }

  const seenCursors = new Set<string>();
  let after = "";
  let idsReceived = 0;
  let batches: string[][] = [];

  // Keep at most eight query pages of IDs in flight for hydration.
  async function hydrateBatches(): Promise<SpotlightFinding[]> {
    if (!batches.length) return [];
    const results = await runWithConcurrency(batches, 8, async (batch) => {
      const url = new URL(`${config.baseUrl}/spotlight/entities/vulnerabilities/v2`);
      for (const id of batch) url.searchParams.append("ids", id);
      const r = await spotlightFetch(url.toString());
      if (!r.ok) throw new Error(`Spotlight entities ${r.status}: ${await r.text().catch(() => r.statusText)}`);
      const j: any = await r.json();
      if (!Array.isArray(j?.resources) || j.resources.length !== batch.length)
        throw new Error(`Spotlight entity hydration incomplete for ${config.label}: expected ${batch.length} findings.`);
      if (j.resources.some((item: any) => !String(item?.id ?? "").trim()))
        throw new Error(`Spotlight source vulnerability ID is missing for ${config.label}.`);
      const returnedIds = new Set(j.resources.map((item: any) => String(item?.id ?? "").trim()));
      if (returnedIds.size !== batch.length || batch.some(id => !returnedIds.has(id)))
        throw new Error(`Spotlight entity hydration IDs mismatch for ${config.label}.`);
      return j.resources.map((item: any) => parseSpotlightResource(config, item)) as SpotlightFinding[];
    });
    batches = [];
    return results.flat();
  }

  // A cursor must make progress. A broken response is an error, not a
  // successful but capped scan. There is deliberately no page-count limit.
  while (true) {
    const url = new URL(`${config.baseUrl}/spotlight/queries/vulnerabilities/v1`);
    url.searchParams.set("filter", "status:'open',status:'reopen'");
    url.searchParams.set("limit", "400");
    if (after) url.searchParams.set("after", after);
    const r = await spotlightFetch(url.toString());
    if (!r.ok) throw new Error(`Spotlight query ${r.status}: ${await r.text().catch(() => r.statusText)}`);
    const j: any = await r.json();
    if (!Array.isArray(j?.resources) || j.resources.some((id: unknown) => typeof id !== "string" || !id))
      throw new Error(`Spotlight query returned invalid IDs for ${config.label}.`);
    const batch = j.resources as string[];
    const next = j?.meta?.pagination?.after ?? "";
    idsReceived += batch.length;
    if (!batch.length && next) throw new Error(`Spotlight query returned an empty page with a cursor for ${config.label}.`);
    const total = j?.meta?.pagination?.total;
    if (!next && typeof total === "number" && Number.isSafeInteger(total) && total > idsReceived)
      throw new Error(`Spotlight pagination incomplete for ${config.label}: received ${idsReceived} of ${total} IDs.`);
    if (batch.length) batches.push(batch);
    if (batches.length === 8) yield await hydrateBatches();
    if (!next) break;
    if (seenCursors.has(next)) throw new Error(`Spotlight pagination cursor repeated for ${config.label}.`);
    seenCursors.add(next);
    after = next;
  }
  if (batches.length) yield await hydrateBatches();
}

// Compatibility collector for existing callers; large imports must consume
// spotlightFindingBatches directly instead of materializing the whole tenant.
export async function spotlightListFindings(config: FalconTenant): Promise<SpotlightListResult> {
  const findings: SpotlightFinding[] = [];
  for await (const batch of spotlightFindingBatches(config)) findings.push(...batch);
  return { findings, truncated: false };
}

// --- Falcon host inventory ---------------------------------------------------
// List Falcon hosts: query device ids (first page gives total → remaining pages
// fire in parallel), then hydrate all ID batches in parallel.
export async function falconListAssets(config: FalconConfig): Promise<FalconAsset[]> {
  const token = await falconToken(config);
  const authHeader = { Authorization: `Bearer ${token}`, Accept: "application/json" };

  const PAGE = 500;

  const fetchIdPage = async (offset: number): Promise<{ ids: string[]; total: number }> => {
    const r = await timedFetch(
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
    const r = await timedFetch(
      `${config.baseUrl}/devices/entities/devices/v2`,
      {
        method: "POST",
        headers: { ...authHeader, "Content-Type": "application/json" },
        body: JSON.stringify({ ids }),
        cache: "no-store",
      },
    );
    if (!r.ok) {
      throw new Error(
        `Falcon devices entities ${r.status}: ${await r.text().catch(() => r.statusText)}`,
      );
    }
    const j: any = await r.json();
    // A device with a sensor but no resolved hostname yet is still a real,
    // Falcon-covered endpoint -- dropping it outright (rather than keeping
    // it keyed by externalId, same as importEndpoints()'s own fallback)
    // silently undercounts real sensor coverage.
    return (j?.resources ?? [])
      .map(normalizeFalconHost)
      .filter((a: FalconAsset) => a.hostname || a.externalId);
  };

  // Fetch first page to learn the total, then fire remaining pages, bounded.
  const first = await fetchIdPage(0);
  if (!first.ids.length) return [];

  const total = first.total || first.ids.length;
  // Falcon's devices/queries/devices/v1 endpoint rejects offset+limit beyond
  // 10,000 (a documented Falcon API ceiling, not a limit this code chose) --
  // paging past it would throw and fail the ENTIRE sync for every device,
  // not just the ones beyond 10k. Cap the walk there and say so loudly
  // instead of crashing (previous behavior) or silently returning short
  // (equally bad): a tenant this size needs a cursor-based rewrite of this
  // endpoint, which is real work, not something to guess at silently here.
  const OFFSET_CEILING = 10_000;
  if (total > OFFSET_CEILING) {
    console.error(
      `[crowdstrike] ${config.baseUrl}: tenant reports ${total} devices, but offset pagination on this endpoint only reaches ${OFFSET_CEILING} -- ${total - OFFSET_CEILING} device(s) will NOT be pulled this sync. Needs a cursor-based rewrite for tenants this size.`,
    );
  }
  const walkTotal = Math.min(total, OFFSET_CEILING);
  const remainingOffsets: number[] = [];
  for (let off = PAGE; off < walkTotal; off += PAGE) remainingOffsets.push(off);

  const restPages = await runWithConcurrency(remainingOffsets, 8, fetchIdPage);
  const allIds = [first.ids, ...restPages.map((p) => p.ids)].flat();

  // Hydrate all ID batches, bounded (API accepts up to 500 per POST).
  const idBatches: string[][] = [];
  for (let i = 0; i < allIds.length; i += PAGE) idBatches.push(allIds.slice(i, i + PAGE));

  const results = await runWithConcurrency(idBatches, 8, hydrateIds);
  return results.flat();
}
