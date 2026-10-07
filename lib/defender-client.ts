import { createHash, createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";

export type DefenderCredentials = { tenantId: string; clientId: string; clientSecret: string };
export type DefenderRecord = {
  sourceId: string; deviceId: string; hostname: string; cve: string;
  severity: string; cvss: number | null; softwareVendor: string; softwareName: string;
  softwareVersion: string; remediation: string; remediationId: string;
  recommendationId: string; firstSeen: string | null; lastSeen: string | null;
  exploitability: string; raw: Record<string, unknown>;
};
export type DefenderDevice = { deviceId: string; hostname: string; os: string; ip: string; lastSeen: string | null };
export class DefenderError extends Error {
  constructor(message: string, public status = 400) { super(message); }
}
const API = "https://api.security.microsoft.com";
const RESOURCE = "https://api.securitycenter.microsoft.com/.default";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validateCredentials(value: DefenderCredentials): DefenderCredentials {
  if (!UUID.test(value.tenantId) || !UUID.test(value.clientId)) throw new DefenderError("Enter valid tenant and application/client IDs.");
  if (!value.clientSecret || value.clientSecret.length > 4096) throw new DefenderError("Enter the client secret value, not its secret ID.");
  return { ...value, tenantId: value.tenantId.toLowerCase(), clientId: value.clientId.toLowerCase() };
}
function key() {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret || secret.length < 32) throw new DefenderError("Server credential encryption is not configured.", 503);
  return Buffer.from(hkdfSync("sha256", secret, "gmi-vuln", "defender-connection-v1", 32));
}
export function sealDefender(value: DefenderCredentials): string {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(validateCredentials(value)), "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), data.toString("base64")].join(".");
}
export function openDefender(value: string): DefenderCredentials {
  try {
    const [version, iv, tag, data] = value.split(".");
    if (version !== "v1") throw new Error();
    const cipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
    cipher.setAuthTag(Buffer.from(tag, "base64"));
    return validateCredentials(JSON.parse(Buffer.concat([cipher.update(Buffer.from(data, "base64")), cipher.final()]).toString("utf8")));
  } catch { throw new DefenderError("Saved Defender credentials cannot be opened. Re-enter the connection credentials.", 503); }
}
function timestamp(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  const date = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : value.replace(" ", "T") + "Z");
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}
export function normalizeDefenderRecord(v: Record<string, unknown>): DefenderRecord | null {
  // Microsoft includes software rows with no CVE. These are inventory, not findings.
  if (v.cveId == null || v.cveId === "") return null;
  const cve = String(v.cveId).toUpperCase(), deviceId = String(v.deviceId ?? "");
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cve) || !deviceId) throw new DefenderError("Defender returned a vulnerability without a valid CVE or device ID. Import was not published.");
  const softwareVendor = String(v.softwareVendor ?? ""), softwareName = String(v.softwareName ?? ""), softwareVersion = String(v.softwareVersion ?? "");
  const score = v.cvssScore == null ? null : Number(v.cvssScore);
  const severity = String(v.vulnerabilitySeverityLevel ?? "Unknown").toUpperCase();
  return {
    sourceId: createHash("sha256").update(JSON.stringify([deviceId, softwareVendor, softwareName, softwareVersion, cve])).digest("hex"),
    deviceId, hostname: String(v.deviceName || deviceId), cve,
    severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(severity) ? severity : "UNKNOWN",
    cvss: score !== null && Number.isFinite(score) && score >= 0 && score <= 10 ? score : null,
    softwareVendor, softwareName, softwareVersion,
    remediation: String(v.recommendedSecurityUpdate ?? "No security update description supplied by Defender."),
    remediationId: String(v.recommendedSecurityUpdateId ?? ""), recommendationId: String(v.recommendationReference ?? ""),
    firstSeen: timestamp(v.firstSeenTimestamp), lastSeen: timestamp(v.lastSeenTimestamp),
    exploitability: String(v.exploitabilityLevel ?? "Unknown"), raw: v,
  };
}
export function safeDefenderUrl(value: string, path: string): string {
  const url = new URL(value, API);
  if (url.protocol !== "https:" || !["api.security.microsoft.com", "api.securitycenter.microsoft.com"].includes(url.hostname) ||
      url.port || url.username || url.password || url.hash || url.pathname !== path) {
    throw new DefenderError("Defender returned an unexpected pagination address. Import was stopped.");
  }
  return url.toString();
}
export function createDefenderClient(credentials: DefenderCredentials, fetcher: typeof fetch = fetch,
  sleep: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  const config = validateCredentials(credentials);
  let token = "", expires = 0;
  async function accessToken() {
    if (token && Date.now() < expires) return token;
    let response: Response;
    try {
      response = await fetcher(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`, {
        method: "POST", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(30_000),
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, scope: RESOURCE, grant_type: "client_credentials" }),
      });
    } catch { throw new DefenderError("Defender authentication could not be reached. Retry the connection test.", 502); }
    if (!response.ok) throw new DefenderError(`Defender authentication returned HTTP ${response.status}. Check tenant ID, client ID, secret value and expiry.`);
    const body = await response.json();
    if (typeof body.access_token !== "string" || !body.access_token) throw new DefenderError("Defender authentication returned no access token.");
    token = body.access_token;
    expires = Date.now() + Math.max(0, (Number(body.expires_in) || 3600) - 60) * 1000;
    return token;
  }
  async function page(url: string, path: string): Promise<{ value: Record<string, unknown>[]; next: string | null }> {
    const target = safeDefenderUrl(url, path);
    for (let attempt = 0; attempt < 4; attempt++) {
      const bearer = await accessToken();
      let response: Response;
      try {
        response = await fetcher(target, { headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" },
          redirect: "error", cache: "no-store", signal: AbortSignal.timeout(30_000) });
      } catch {
        if (attempt < 3) { await sleep(1000 * 2 ** attempt); continue; }
        throw new DefenderError("Defender request timed out or could not be reached. The previous completed import is retained.", 502);
      }
      if (response.status === 401 && attempt < 3) { token = ""; continue; }
      if ((response.status === 429 || response.status >= 500) && attempt < 3) {
        const retry = response.headers.get("retry-after");
        const wait = retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : retry ? Date.parse(retry) - Date.now() : 1000 * 2 ** attempt;
        await sleep(Math.min(60_000, Math.max(1000, Number.isFinite(wait) ? wait : 1000)));
        continue;
      }
      if (!response.ok) throw new DefenderError(`Defender ${path === "/api/machines" ? "device inventory" : "vulnerability export"} returned HTTP ${response.status}. ${response.status === 403 ? "Check application permissions, administrator consent and Defender licensing." : "Retry after checking the connection."}`, 502);
      const body = await response.json();
      if (!Array.isArray(body.value) || body.value.some((v: unknown) => !v || typeof v !== "object")) throw new DefenderError("Defender returned an invalid page; import was not published.");
      const next = body["@odata.nextLink"];
      if (next != null && typeof next !== "string") throw new DefenderError("Defender returned invalid pagination; import was not published.");
      return { value: body.value, next: next ? safeDefenderUrl(next, path) : null };
    }
    throw new DefenderError("Defender request could not complete.", 502);
  }
  async function* batches(kind: "devices" | "findings") {
    const path = kind === "devices" ? "/api/machines" : "/api/machines/SoftwareVulnerabilitiesByMachine";
    let url: string | null = `${API}${path}?${kind === "devices" ? "$top=1000&$skip=0" : "pageSize=1000"}`;
    const visited = new Set<string>();
    let offset = 0;
    while (url) {
      if (visited.has(url) || visited.size >= 100_000) throw new DefenderError("Defender pagination did not complete. Previous results are retained.");
      visited.add(url);
      const result = await page(url, path);
      yield result.value;
      offset += result.value.length;
      url = result.next ?? (kind === "devices" && result.value.length === 1000 ? `${API}${path}?$top=1000&$skip=${offset}` : null);
    }
  }
  return {
    batches,
    test: async () => {
      await page(`${API}/api/machines?$top=1`, "/api/machines");
      await page(`${API}/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=1`, "/api/machines/SoftwareVulnerabilitiesByMachine");
      return { ok: true, message: "Authentication, device inventory and vulnerability export access verified. No records imported." };
    },
  };
}
