import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { DashboardError, parseQueryInput, type QueryInput, type QueryResult } from "./elastic-dashboard";
import { applyEpss, CROWDSTRIKE_DATASETS, FALCON_REGIONS, type CrowdStrikeConnection, type Vulnerability } from "./crowdstrike-dashboard";
import { buildPatchConsolidation, buildPatchRequest, normalizePatchFinding, normalizeRemediation, parseConsolidationInput, parsePatchInput, patchRecommendationIds, type PatchConsolidation, type PatchFinding, type PatchRequest } from "./patch-request";
import { fetchEpss } from "./threat";

export function parseCrowdStrikeConnection(value: unknown): CrowdStrikeConnection {
  const body = value as CrowdStrikeConnection | null;
  if (!body || !Object.hasOwn(FALCON_REGIONS, body.region)) throw new DashboardError("Choose your CrowdStrike cloud region.");
  for (const field of ["clientId", "clientSecret"] as const) {
    if (typeof body[field] !== "string" || !body[field].trim() || body[field].length > 4096 || /\s/.test(body[field].trim())) {
      throw new DashboardError("Enter the CrowdStrike client ID and client secret.");
    }
  }
  return { region: body.region, clientId: body.clientId.trim(), clientSecret: body.clientSecret.trim() };
}

function key() {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret || secret.length < 32) throw new DashboardError("Server encryption is not configured.");
  return Buffer.from(hkdfSync("sha256", secret, "gmi-vuln", "crowdstrike-dashboard-connection-v1", 32));
}
export function sealCrowdStrike(connection: CrowdStrikeConnection): string {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(connection), "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), data.toString("base64")].join(".");
}
export function openCrowdStrike(value: string): CrowdStrikeConnection {
  try {
    const [version, iv, tag, data] = value.split(".");
    if (version !== "v1") throw new Error();
    const cipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
    cipher.setAuthTag(Buffer.from(tag, "base64"));
    return parseCrowdStrikeConnection(JSON.parse(Buffer.concat([cipher.update(Buffer.from(data, "base64")), cipher.final()]).toString("utf8")));
  } catch { throw new DashboardError("The saved CrowdStrike connection cannot be opened. Enter the credentials again."); }
}

function failure(status: number, body: Record<string, any>, secrets: string[]): DashboardError {
  if (status === 401 || status === 403) return new DashboardError("CrowdStrike rejected access. Check the cloud region, client credentials, and Vulnerabilities: Read permission.");
  if (status === 429) return new DashboardError("CrowdStrike's rate limit was reached. Retry later or reduce the refresh frequency.", 429);
  let reason = Array.isArray(body.errors) ? body.errors.map((e: any) => typeof e?.message === "string" ? e.message : "").join(" ") : "";
  for (const secret of secrets) if (secret) reason = reason.split(secret).join("[redacted]");
  reason = reason.replace(/Bearer\s+\S+/gi, "[redacted]").replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 600);
  return new DashboardError(`CrowdStrike query failed (HTTP ${status}). ${reason || "Check the FQL filter and try again."}`);
}

async function jsonRequest(url: URL, init: RequestInit, deadline: number, secrets: string[]): Promise<Record<string, any>> {
  for (let retry = 0; retry < 3; retry++) {
    if (Date.now() >= deadline) throw new DashboardError("CrowdStrike collection exceeded five minutes. Narrow the filter or reduce the dataset size. No partial totals were saved.");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(20_000, deadline - Date.now()));
    let response: Response;
    let body: Record<string, any>;
    try {
      response = await fetch(url, { ...init, redirect: "error", cache: "no-store", signal: controller.signal });
      const reader = response.body?.getReader();
      if (!reader) throw new DashboardError("CrowdStrike returned an empty response.");
      let size = 0; const chunks: Uint8Array[] = [];
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 8 * 1024 * 1024) { await reader.cancel(); throw new DashboardError("CrowdStrike returned an oversized page. No partial totals were saved."); }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
      catch { throw new DashboardError(`CrowdStrike returned an invalid response (HTTP ${response.status}).`); }
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new DashboardError("CrowdStrike returned an invalid response.");
    } catch (error) {
      if (error instanceof DashboardError) throw error;
      // Retrying a GET repeats only the current page. Already collected pages
      // are retained, and all attempts remain inside the collection deadline.
      if ((init.method ?? "GET") === "GET" && retry < 2 && Date.now() + 1000 < deadline) {
        await delay(1000); continue;
      }
      throw new DashboardError("CrowdStrike could not be reached or the request timed out. Retry later.");
    } finally { clearTimeout(timer); }
    if ((response.status === 429 || response.status >= 500) && retry < 2) {
      const retryAfter = response.headers.get("retry-after");
      const seconds = retryAfter ? (/^\d+$/.test(retryAfter) ? Number(retryAfter) : (Date.parse(retryAfter) - Date.now()) / 1000) : 2 ** (retry + 1);
      if (Number.isFinite(seconds) && seconds >= 0 && seconds <= 30 && Date.now() + seconds * 1000 < deadline) {
        await delay(seconds * 1000); continue;
      }
    }
    if (!response.ok || (Array.isArray(body.errors) && body.errors.length)) throw failure(response.status, body, secrets);
    return body;
  }
  throw new DashboardError("CrowdStrike collection failed.");
}

async function session(connection: CrowdStrikeConnection, deadline: number) {
  const config = parseCrowdStrikeConnection(connection);
  const secrets = [config.clientId, config.clientSecret];
  const base = FALCON_REGIONS[config.region];
  const auth = await jsonRequest(new URL(`${base}/oauth2/token`), {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret }),
  }, deadline, secrets);
  if (typeof auth.access_token !== "string" || !auth.access_token) throw new DashboardError("CrowdStrike returned no access token.");
  secrets.push(auth.access_token);
  return { base, secrets, headers: { Authorization: `Bearer ${auth.access_token}`, Accept: "application/json" } };
}

export async function testCrowdStrikeConnection(connection: CrowdStrikeConnection): Promise<void> {
  const deadline = Date.now() + 45_000;
  const auth = await session(connection, deadline);
  const url = new URL(`${auth.base}${CROWDSTRIKE_DATASETS.vulnerabilities.path}`);
  url.searchParams.set("filter", "status:['open','reopen']"); url.searchParams.set("limit", "1");
  for (const facet of CROWDSTRIKE_DATASETS.vulnerabilities.facets) url.searchParams.append("facet", facet);
  const result = await jsonRequest(url, { headers: auth.headers }, deadline, auth.secrets);
  if (!Array.isArray(result.resources)) throw new DashboardError("CrowdStrike did not return vulnerability data.");
}

// EPSS is unknown until fetched (a separate batched call to FIRST.org), so it
// is folded in after collection rather than at parse time. The cache is kept
// across severity batches in the cve-devices loop so each CVE is only looked
// up once per query, however many times this query re-enriches records.
async function enrichEpss(records: Map<string, Vulnerability>, cache: Map<string, number>): Promise<void> {
  const candidates = [...records.values()].map((row) => row.cve).filter((cve) => cve && !cache.has(cve.toUpperCase()));
  const missing = [...new Set(candidates)];
  if (missing.length) {
    const fetched = await fetchEpss(missing);
    for (const [cve, score] of fetched) cache.set(cve, score);
  }
  applyEpss(records.values(), cache);
}

export async function executeCrowdStrike(connection: CrowdStrikeConnection, value: QueryInput, budgetMs = 300_000): Promise<QueryResult> {
  const input = parseQueryInput(value), options = input.crowdstrike;
  if (!options) throw new DashboardError("Choose a CrowdStrike dataset.");
  const dataset = CROWDSTRIKE_DATASETS[options.dataset];
  const deadline = Date.now() + budgetMs, auth = await session(connection, deadline);
  if (options.view === "severity-counts") {
    // Read the API's matching population total, not the length of the first page.
    // No entity collection or local 250,000-record cap is needed for these counts.
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
    const counts: number[] = [];
    for (const severity of severities) {
      const url = new URL(`${auth.base}/spotlight/queries/vulnerabilities/v1`);
      url.searchParams.set("filter", `(${input.query})+cve.severity:'${severity}'`);
      url.searchParams.set("limit", "1");
      const body = await jsonRequest(url, { headers: auth.headers }, deadline, auth.secrets);
      const total = body.meta?.pagination?.total;
      if (!Array.isArray(body.resources) || !Number.isSafeInteger(total) || total < 0) {
        throw new DashboardError("CrowdStrike did not return a valid severity total. No partial totals were saved.");
      }
      counts.push(total);
    }
    return { columns: severities.map((name) => ({ name: name.toLowerCase(), type: "long" })),
      rows: [counts], truncated: false,
      note: "CrowdStrike CVSS severity counts for this filter, one finding per vulnerability instance. Counts are separate API observations collected during this refresh, not a single atomic snapshot. None and Unknown are retained; these are not GMI priorities or ExPRT ratings." };
  }
  if (options.view === "cve-devices") {
    const records = new Map<string, Vulnerability>(), epssCache = new Map<string, number>();
    // Severity is the primary ordering key. Finish each severity completely;
    // lower severities cannot displace a full top-N from completed higher ones.
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]) {
      const batch = await collectRecords(auth, deadline, `(${input.query})+cve.severity:'${severity}'`, ["cve"], 1000);
      for (const [id, row] of batch) {
        if (row.severity !== severity || records.has(id)) throw new DashboardError("CrowdStrike findings changed severity during collection. Retry; no partial device counts were saved.");
        records.set(id, row);
      }
      await enrichEpss(records, epssCache);
      const result = dataset.summarize(records.values(), options);
      if (result.rows.length >= options.top) return result;
    }
    return dataset.summarize(records.values(), options);
  }
  const records = await collectRecords(auth, deadline, input.query, dataset.facets, 500);
  if (options.view === "patch-worklist") await enrichEpss(records, new Map());
  return dataset.summarize(records.values(), options);
}

async function collectRecords(auth: Awaited<ReturnType<typeof session>>, deadline: number, filter: string, facets: string[], limit: number): Promise<Map<string, Vulnerability>> {
  const dataset = CROWDSTRIKE_DATASETS.vulnerabilities;
  const records = new Map<string, Vulnerability>(), cursors = new Set<string>();
  let after = "", received = 0, expected = 0;
  for (let page = 0; page < 500; page++) {
    const url = new URL(`${auth.base}${dataset.path}`);
    url.searchParams.set("filter", filter); url.searchParams.set("limit", String(limit));
    // The Spotlight API uses multi-value query encoding, not a comma-separated value.
    for (const facet of facets) url.searchParams.append("facet", facet);
    if (after) url.searchParams.set("after", after);
    const body = await jsonRequest(url, { headers: auth.headers }, deadline, auth.secrets);
    const pagination = body.meta?.pagination;
    if (!Array.isArray(body.resources) || !pagination || typeof pagination !== "object") throw new DashboardError("CrowdStrike returned invalid pagination. No totals were saved.");
    if (!Number.isSafeInteger(pagination.total) || pagination.total < 0) throw new DashboardError("CrowdStrike returned an invalid total count. No totals were saved.");
    expected = Math.max(expected, pagination.total);
    if (expected > 250_000) throw new DashboardError("This filter matches more than 250,000 findings. Narrow the filter before saving a tile.");
    received += body.resources.length;
    if (received > 250_000) throw new DashboardError("CrowdStrike collection exceeds 250,000 records. Narrow the filter. No partial totals were saved.");
    for (const raw of body.resources) {
      const row = dataset.normalize(raw), key = JSON.stringify([row.cid, row.id]), old = records.get(key);
      if (!old) records.set(key, row);
      else if (JSON.stringify(old) !== JSON.stringify(row)) {
        const previous = Date.parse(old.updated), next = Date.parse(row.updated);
        if (!Number.isFinite(previous) || !Number.isFinite(next) || previous === next) throw new DashboardError("CrowdStrike returned conflicting copies of a finding without a clear update order. Retry; no totals were saved.");
        if (next > previous) records.set(key, row);
      }
    }
    if (pagination.after !== undefined && pagination.after !== null && typeof pagination.after !== "string") throw new DashboardError("CrowdStrike returned an invalid page cursor.");
    after = pagination.after || "";
    if (!after || records.size >= expected) {
      if (records.size < expected) throw new DashboardError("CrowdStrike pagination ended before all findings were received. Retry; no partial totals were saved.");
      return records;
    }
    if (!body.resources.length || cursors.has(after)) throw new DashboardError("CrowdStrike pagination did not advance. Retry; no partial totals were saved.");
    cursors.add(after);
  }
  throw new DashboardError("CrowdStrike collection reached the page limit. Narrow the filter. No partial totals were saved.");
}

async function collectPatchFindings(auth: Awaited<ReturnType<typeof session>>, deadline: number, cve: string, tenantId?: string): Promise<Map<string, PatchFinding>> {
  const records = new Map<string, PatchFinding>(), cursors = new Set<string>();
  let after = "", expected: number | undefined, received = 0, bytes = 0, complete = false;
  for (let page = 0; page < 500; page++) {
    const url = new URL(`${auth.base}/spotlight/combined/vulnerabilities/v1`);
    url.searchParams.set("filter", `cve.id:'${cve}'+status:['open','reopen']${tenantId ? `+cid:'${tenantId}'` : ""}`);
    url.searchParams.set("limit", "500");
    for (const facet of ["cve", "host_info", "remediation"]) url.searchParams.append("facet", facet);
    if (after) url.searchParams.set("after", after);
    const body = await jsonRequest(url, { headers: auth.headers }, deadline, auth.secrets);
    const pagination = body.meta?.pagination;
    if (!Array.isArray(body.resources) || !Number.isSafeInteger(pagination?.total) || pagination.total < 0) throw new DashboardError("CrowdStrike returned invalid patch-request pagination. No partial export was prepared.");
    if (expected !== undefined && expected !== pagination.total) throw new DashboardError("The matching CVE population changed during collection. Retry to collect all affected hosts.");
    expected = pagination.total;
    received += body.resources.length;
    if (expected! > 250_000 || received > 250_000) throw new DashboardError("This CVE exceeds the 250,000-finding collection limit. No partial export was prepared.");
    for (const raw of body.resources) {
      const row = normalizePatchFinding(raw, cve), key = JSON.stringify([row.cid, row.id]), old = records.get(key);
      if (tenantId && row.cid !== tenantId) throw new DashboardError("CrowdStrike returned a finding for another tenant. No export was prepared.");
      if (old && JSON.stringify(old) !== JSON.stringify(row)) throw new DashboardError("A finding changed during collection. Retry to prepare a consistent patch request.");
      if (!old) {
        bytes += Buffer.byteLength(JSON.stringify(row));
        if (bytes > 32 * 1024 * 1024) throw new DashboardError("The CVE details exceed the 32 MiB collection limit. No partial export was prepared.");
        records.set(key, row);
      }
    }
    if (pagination.after !== undefined && pagination.after !== null && typeof pagination.after !== "string") throw new DashboardError("CrowdStrike returned an invalid page cursor.");
    after = pagination.after || "";
    if (!after || records.size >= expected!) {
      if (records.size !== expected) throw new DashboardError("CrowdStrike pagination ended without all matching findings. No partial export was prepared.");
      complete = true; break;
    }
    if (!body.resources.length || cursors.has(after)) throw new DashboardError("CrowdStrike pagination did not advance. No partial export was prepared.");
    cursors.add(after);
  }
  if (!complete) throw new DashboardError("CrowdStrike reached the page limit. No partial export was prepared.");
  return records;
}

// The remediation facet usually supplies the entities. Resolve any referenced
// IDs still missing an action with the documented remediation entity endpoint.
async function hydrateRemediations(auth: Awaited<ReturnType<typeof session>>, deadline: number, records: Iterable<PatchFinding>): Promise<void> {
  const rows = [...records];
  const missing = new Set<string>();
  for (const row of rows) {
    const known = new Map(row.remediations.map((r) => [r.id, r]));
    for (const id of patchRecommendationIds(row)) if (!known.get(id)?.action) missing.add(id);
  }
  const hydrated = new Map<string, ReturnType<typeof normalizeRemediation>>();
  const ids = [...missing];
  for (let start = 0; start < ids.length; start += 100) {
    const batch = ids.slice(start, start + 100), url = new URL(`${auth.base}/spotlight/entities/remediations/v2`);
    for (const id of batch) url.searchParams.append("ids", id);
    const body = await jsonRequest(url, { headers: auth.headers }, deadline, auth.secrets);
    if (!Array.isArray(body.resources)) throw new DashboardError("CrowdStrike did not return remediation details. No patch request was prepared.");
    for (const raw of body.resources) {
      const remediation = normalizeRemediation(raw);
      if (!batch.includes(remediation.id)) throw new DashboardError("CrowdStrike returned an unexpected remediation identifier.");
      hydrated.set(remediation.id, remediation);
    }
    if (batch.some((id) => !hydrated.has(id))) throw new DashboardError("CrowdStrike did not return all referenced remediations. No partial export was prepared.");
  }
  for (const row of rows) {
    const known = new Map(row.remediations.map((r) => [r.id, r]));
    for (const id of patchRecommendationIds(row)) {
      if (!known.get(id)?.action && hydrated.has(id)) known.set(id, hydrated.get(id)!);
    }
    row.remediations = [...known.values()];
  }
}

export async function executePatchRequest(connection: CrowdStrikeConnection, value: unknown, budgetMs = 300_000): Promise<PatchRequest> {
  const { cve, tenantId } = parsePatchInput(value), startedAt = new Date().toISOString();
  const deadline = Date.now() + budgetMs, auth = await session(connection, deadline);
  const records = await collectPatchFindings(auth, deadline, cve, tenantId);
  await hydrateRemediations(auth, deadline, records.values());
  if (Date.now() >= deadline) throw new DashboardError("Patch request collection exceeded five minutes. Retry; no partial export was prepared.");
  return buildPatchRequest(cve, [...records.values()], connection.region, startedAt, new Date().toISOString());
}

export async function executePatchConsolidation(connection: CrowdStrikeConnection, value: unknown, alreadyTicketed: Set<string> = new Set(), budgetMs = 360_000): Promise<PatchConsolidation> {
  const { cves, tenantId } = parseConsolidationInput(value), startedAt = new Date().toISOString();
  const deadline = Date.now() + budgetMs, auth = await session(connection, deadline);
  const all: PatchFinding[] = [];
  for (const cve of cves) {
    const records = await collectPatchFindings(auth, deadline, cve, tenantId);
    all.push(...records.values());
    if (all.length > 500_000) throw new DashboardError("This CVE set exceeds the 500,000-finding combined collection limit. Choose fewer CVEs.");
  }
  await hydrateRemediations(auth, deadline, all);
  if (Date.now() >= deadline) throw new DashboardError("Consolidation collection exceeded the time budget. Retry; no partial export was prepared.");
  return buildPatchConsolidation(cves, all, connection.region, startedAt, new Date().toISOString(), alreadyTicketed);
}

// Closed-loop check: re-collects each CVE's currently open/reopened findings
// (unhydrated — remediation detail is not needed to answer "is it still
// open") and reports which of the ticket's originally scoped devices still
// show up. Absence from the current open population is the signal a device
// is fixed; it is not a positive confirmation the specific patch ran.
export async function verifyPatchFix(connection: CrowdStrikeConnection, cves: string[], hostScope: string[], tenantId: string, budgetMs = 120_000): Promise<{ checkedAt: string; stillOpenHosts: string[]; scopedDevices: number }> {
  const deadline = Date.now() + budgetMs, auth = await session(connection, deadline);
  const scoped = new Set(hostScope), stillOpen = new Set<string>();
  for (const cve of cves) {
    const records = await collectPatchFindings(auth, deadline, cve, tenantId);
    for (const row of records.values()) {
      const key = JSON.stringify([row.cid, row.hostId]);
      if (scoped.has(key)) stillOpen.add(key);
    }
  }
  return { checkedAt: new Date().toISOString(), stillOpenHosts: [...stillOpen].sort(), scopedDevices: scoped.size };
}
