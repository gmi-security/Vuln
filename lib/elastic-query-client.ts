import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { DashboardError, parseQueryResult, validateQuery, type QueryResult } from "./elastic-dashboard";

export type ElasticConnection = { endpoint: string; apiKey: string };

export function normalizeEndpoint(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw new DashboardError("Enter the Elasticsearch HTTPS endpoint.");
  let url: URL;
  try { url = new URL(value); } catch { throw new DashboardError("Enter a valid Elasticsearch HTTPS endpoint."); }
  if (/\.kb\..*\.found\.io$/.test(url.hostname)) throw new DashboardError("That is a Kibana address. Copy the Elasticsearch endpoint from your Elastic deployment.");
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
      url.hostname === "localhost" || url.hostname.endsWith(".localhost")) {
    throw new DashboardError("Use an HTTPS Elasticsearch endpoint without credentials, query parameters, or fragments.");
  }
  return url.toString().replace(/\/+$/, "");
}

// The connection UI supports public HTTPS endpoints. Resolve and pin an IPv4
// address for each request so redirects or DNS rebinding cannot reach metadata,
// loopback, or internal services. Private Elastic networks need explicit setup.
export function isPublicIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
}

function encryptionKey(): Buffer {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret || secret.length < 32) throw new DashboardError("Server encryption is not configured.");
  return Buffer.from(hkdfSync("sha256", secret, "gmi-vuln", "elastic-dashboard-connection-v1", 32));
}

export function sealConnection(connection: ElasticConnection): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(connection), "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), data.toString("base64")].join(".");
}

export function openConnection(value: string): ElasticConnection {
  try {
    const [version, iv, tag, data] = value.split(".");
    if (version !== "v1") throw new DashboardError("Invalid encrypted value.");
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(data, "base64")), decipher.final()]).toString("utf8"));
  } catch { throw new DashboardError("The saved connection cannot be opened. An administrator must reconnect Elasticsearch."); }
}

export function elasticFailure(status: number, body: unknown, apiKey: string): DashboardError {
  if (status === 401 || status === 403) return new DashboardError("Elastic rejected the API key or its index permissions.");
  let reason = "";
  if (body && typeof body === "object") {
    const error = (body as { error?: { reason?: unknown; type?: unknown } }).error;
    if (typeof error?.reason === "string") reason = error.reason;
  }
  reason = reason.split(apiKey).join("[redacted]").replace(/(?:ApiKey|Bearer)\s+\S+/gi, "[redacted]")
    .replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 1200);
  return new DashboardError(`Elastic rejected the query (HTTP ${status}). ${reason || "Check the ES|QL syntax, index access, and Elasticsearch version."}`);
}

export async function elasticJsonRequest(connection: ElasticConnection, path: string, method: "POST" | "GET" | "DELETE", body?: unknown): Promise<{ body: Record<string, unknown>; warning: boolean }> {
  const endpoint = normalizeEndpoint(connection.endpoint);
  const url = new URL(`${endpoint}${path}`);
  const resolved = await Promise.race([
    lookup(url.hostname, { family: 4 }),
    new Promise<never>((_, reject) => { const timer = setTimeout(() => reject(new DashboardError("Elastic DNS lookup timed out.")), 5000); timer.unref(); }),
  ]);
  if (!isPublicIPv4(resolved.address)) throw new DashboardError("This connection requires a public Elasticsearch HTTPS endpoint.");
  const payload = body === undefined ? "" : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method, family: 4,
      lookup: (_hostname, _options, callback) => callback(null, resolved.address, 4),
      headers: { Authorization: `ApiKey ${connection.apiKey}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
    }, (response) => {
      let size = 0;
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 2 * 1024 * 1024) req.destroy(new DashboardError("Elastic result exceeds the 2 MiB tile limit. Aggregate or narrow the query."));
        else chunks.push(chunk);
      });
      response.on("error", () => reject(new DashboardError("Elastic response was interrupted.")));
      response.on("end", () => {
        try {
          let parsed: Record<string, unknown>;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
          catch { if (response.statusCode !== 200) throw elasticFailure(response.statusCode ?? 502, null, connection.apiKey); throw new DashboardError("Elastic returned invalid JSON."); }
          if (response.statusCode !== 200) throw elasticFailure(response.statusCode ?? 502, parsed, connection.apiKey);
          if (!parsed || typeof parsed !== "object") throw new DashboardError("Elastic returned an invalid response.");
          resolve({ body: parsed, warning: Boolean(response.headers.warning) });
        }
        catch (error) { reject(error instanceof SyntaxError ? new DashboardError("Elastic returned invalid JSON.") : error); }
      });
    });
    const timeout = setTimeout(() => req.destroy(new DashboardError("Elastic HTTP request timed out after 20 seconds.")), 20_000);
    req.on("close", () => clearTimeout(timeout));
    req.on("error", (error) => reject(new DashboardError(error.message.startsWith("Elastic ") ? error.message : "Could not reach Elasticsearch over verified HTTPS.")));
    req.end(payload);
  });
}

export async function executeEsql(connection: ElasticConnection, query: string): Promise<QueryResult> {
  const reply = await elasticJsonRequest(connection, "/_query?format=json&allow_partial_results=false", "POST", {
    query: `${validateQuery(query)}\n| LIMIT 101`, columnar: false,
  });
  return parseQueryResult(reply.body, reply.warning);
}
