import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { DashboardError } from "./elastic-dashboard";
import { isPublicIPv4 } from "./elastic-query-client";

export type ConnectWiseConnection = { endpoint: string; companyId: string; clientId: string; publicKey: string; privateKey: string; authMode?: "encoded" };
export type CWOption = { id: number; name: string; identifier?: string };
export type TicketRouting = { companyId: number; boardId: number; teamId?: number };
export type CWDefaults = Omit<Partial<TicketRouting>, "companyId">;
export type CWRecord = Record<string, any>;

export function normalizeCWEndpoint(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw new DashboardError("Enter the ConnectWise PSA HTTPS API address.");
  let url: URL;
  try { url = new URL(value.trim()); } catch { throw new DashboardError("Enter a valid ConnectWise HTTPS address."); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || (url.port && url.port !== "443") || url.hostname === "localhost" || url.hostname.endsWith(".localhost")) {
    throw new DashboardError("Use a public HTTPS ConnectWise address without credentials or query parameters.");
  }
  if (/^(na|eu|aus)\.myconnectwise\.net$/.test(url.hostname)) url.hostname = `api-${url.hostname}`;
  if (!url.pathname || url.pathname === "/") url.pathname = "/v4_6_release/apis/3.0";
  url.pathname = url.pathname.replace(/\/+$/, "");
  if (!/^\/v[a-z0-9_.-]+\/apis\/3\.0$/i.test(url.pathname)) throw new DashboardError("Use the API base address ending in /v4_6_release/apis/3.0 (or your hosted version).");
  return url.toString().replace(/\/+$/, "");
}

export function parseCWAuth(value: unknown): Pick<ConnectWiseConnection, "companyId" | "publicKey" | "privateKey"> {
  const fail = () => new DashboardError("Enter a valid CW_AUTH value containing Base64-encoded companyID+publicKey:privateKey.");
  if (typeof value !== "string" || value.length > 20000) throw fail();
  const encoded = value.trim().replace(/^Basic\s+/i, "");
  if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 === 1) throw fail();
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) throw fail();
  const decoded = bytes.toString("utf8");
  if (!Buffer.from(decoded).equals(bytes) || /[\s\x00-\x1f\x7f]/.test(decoded)) throw fail();
  const plus = decoded.indexOf("+"), colon = decoded.indexOf(":", plus + 1);
  if (plus < 1 || colon <= plus + 1 || colon === decoded.length - 1 || decoded.slice(0, plus).includes(":")) throw fail();
  return { companyId: decoded.slice(0, plus), publicKey: decoded.slice(plus + 1, colon), privateKey: decoded.slice(colon + 1) };
}

export function parseCWConnection(value: unknown): ConnectWiseConnection {
  const body = value as Record<string, unknown> | null;
  if (!body) throw new DashboardError("Enter your ConnectWise connection settings.");
  const result = { endpoint: normalizeCWEndpoint(body.endpoint) } as ConnectWiseConnection;
  for (const field of ["companyId", "clientId", "publicKey", "privateKey"] as const) {
    const v = body[field];
    if (typeof v !== "string" || !v.trim() || v.length > 4096 || /[\s\x00-\x1f\x7f]/.test(v.trim()) || (["companyId", "publicKey"].includes(field) && /[:+]/.test(v))) throw new DashboardError(`Enter a valid ConnectWise ${field === "companyId" ? "login company ID" : field === "clientId" ? "Client ID" : field === "publicKey" ? "public key" : "private key"}.`);
    result[field] = v.trim();
  }
  if (body.authMode === "encoded") result.authMode = "encoded";
  return result;
}
function key() {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret || secret.length < 32) throw new DashboardError("Server encryption is not configured.");
  return Buffer.from(hkdfSync("sha256", secret, "gmi-vuln", "connectwise-connection-v1", 32));
}
export function sealCWConnection(connection: ConnectWiseConnection): string {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(connection), "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), data.toString("base64")].join(".");
}
export function openCWConnection(value: string): ConnectWiseConnection {
  try {
    const [version, iv, tag, data] = value.split(".");
    if (version !== "v1") throw new Error();
    const cipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64"));
    cipher.setAuthTag(Buffer.from(tag, "base64"));
    return parseCWConnection(JSON.parse(Buffer.concat([cipher.update(Buffer.from(data, "base64")), cipher.final()]).toString("utf8")));
  } catch { throw new DashboardError("The ConnectWise connection cannot be opened. Enter the keys again."); }
}
export function cwTarget(connection: ConnectWiseConnection): string {
  return createHash("sha256").update(new URL(connection.endpoint).host.toLowerCase() + "/" + connection.companyId.toLowerCase()).digest("hex");
}
export class CWRequestError extends DashboardError {
  constructor(message: string, public uncertain: boolean, status = 502) { super(message, status); }
}
export function cwFailure(status: number, value: unknown, connection: ConnectWiseConnection): CWRequestError {
  const body = value as CWRecord | null;
  let message = typeof body?.message === "string" ? body.message : Array.isArray(body?.errors) ? body.errors.map((e: CWRecord) => typeof e?.message === "string" ? e.message : "").join(" ") : "Check the API member permissions and routing settings.";
  const auth = Buffer.from(`${connection.companyId}+${connection.publicKey}:${connection.privateKey}`).toString("base64");
  for (const secret of [connection.privateKey, connection.publicKey, connection.clientId, auth]) if (secret) message = message.split(secret).join("[redacted]");
  message = message.replace(/(?:Basic|Bearer)\s+\S+/gi, "[redacted]").replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 500);
  return new CWRequestError(`ConnectWise returned HTTP ${status}. ${message}`, status >= 500 || status === 408, status === 401 || status === 403 ? 400 : 502);
}

// DNS is validated and pinned for every request; redirects are never followed.
// Never automatically retry writes: a timeout may have happened after creation.
export async function cwRequest(connection: ConnectWiseConnection, path: string, method: "GET" | "POST" = "GET", body?: unknown): Promise<any> {
  const endpoint = normalizeCWEndpoint(connection.endpoint);
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("..")) throw new DashboardError("Invalid ConnectWise resource.");
  let resolved: { address: string; family: number };
  try {
    resolved = await Promise.race([lookup(new URL(endpoint).hostname, { family: 4 }), new Promise<never>((_, reject) => {
      const timer = setTimeout(() => reject(new DashboardError("ConnectWise DNS lookup timed out.")), 5000); timer.unref();
    })]);
  } catch { throw new CWRequestError("Could not resolve the ConnectWise server.", false); }
  if (!isPublicIPv4(resolved.address)) throw new CWRequestError("ConnectWise must use a public HTTPS address.", false, 400);
  let payload = Buffer.alloc(0), contentType = "application/json";
  if (body instanceof FormData) {
    const encoded = new Response(body);
    contentType = encoded.headers.get("content-type")!;
    payload = Buffer.from(await encoded.arrayBuffer());
  } else if (body !== undefined) payload = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = request(new URL(endpoint + path), { method, family: 4, lookup: (_hostname, _options, cb) => cb(null, resolved.address, 4),
      headers: { Authorization: `Basic ${Buffer.from(`${connection.companyId}+${connection.publicKey}:${connection.privateKey}`).toString("base64")}`,
        clientId: connection.clientId, Accept: "application/json", "Content-Type": contentType, "Content-Length": payload.byteLength } }, res => {
      let bytes = 0; const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 8 * 1024 * 1024) req.destroy(); else chunks.push(chunk); });
      res.on("error", () => reject(new CWRequestError("ConnectWise response was interrupted. Check the saved request before retrying.", method === "POST")));
      res.on("end", () => {
        let parsed: unknown;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { reject(new CWRequestError(`ConnectWise returned an unreadable response (HTTP ${res.statusCode}).`, method === "POST")); return; }
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) { reject(cwFailure(res.statusCode ?? 502, parsed, connection)); return; }
        resolve(parsed);
      });
    });
    const timer = setTimeout(() => req.destroy(), 15_000);
    req.on("close", () => clearTimeout(timer));
    req.on("error", () => reject(new CWRequestError("ConnectWise could not be reached or timed out. Check the saved request before retrying.", method === "POST")));
    req.end(payload);
  });
}
export const cwId = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
export function parseRouting(value: unknown): TicketRouting {
  const body = value as TicketRouting | null;
  if (!body || ![body.companyId, body.boardId].every(cwId) || (body.teamId !== undefined && !cwId(body.teamId))) throw new DashboardError("Choose a company and board from ConnectWise.");
  // Ignore legacy status/priority selections; ConnectWise applies its defaults.
  return { companyId: body.companyId, boardId: body.boardId, ...(body.teamId ? { teamId: body.teamId } : {}) };
}
export async function cwOptions(connection: ConnectWiseConnection, kind: string, boardId?: number, page = 1, search = "", selectedId?: number) {
  // BoardInfo uses ticket inquiry access rather than the board setup-table API.
  const paths: Record<string, string> = { boards: "/service/info/boards", priorities: "/service/priorities", companies: "/company/companies" };
  let path = Object.hasOwn(paths, kind) ? paths[kind] : "";
  if (["statuses", "teams"].includes(kind) && cwId(boardId)) path = `/service/boards/${boardId}/${kind}`;
  if (!path || !Number.isInteger(page) || page < 1 || page > 10000 || search.length > 100 || /["\\\x00-\x1f]/.test(search)) throw new DashboardError("Invalid ConnectWise lookup.");
  const params = new URLSearchParams({ page: String(page), pageSize: "100", orderBy: "name asc" });
  if (kind === "companies" && search.trim()) params.set("conditions", `name contains "${search.trim()}"`);
  const rows = await cwRequest(connection, `${path}?${params}`);
  if (!Array.isArray(rows)) throw new DashboardError("ConnectWise did not return a valid selection list.", 502);
  const more = rows.length === 100;
  if (selectedId !== undefined && !cwId(selectedId)) throw new DashboardError("Invalid selected ConnectWise option.");
  if (selectedId && !rows.some(row => row.id === selectedId)) {
    const selected = await cwRequest(connection, `${path}/${selectedId}`);
    if (selected?.id !== selectedId) throw new DashboardError("ConnectWise returned an unexpected saved option.", 502);
    rows.push(selected);
  }
  const seen = new Set<number>();
  const options: CWOption[] = [];
  for (const row of rows) {
    if (!cwId(row.id) || typeof row.name !== "string" || !row.name.trim() || seen.has(row.id)) throw new DashboardError("ConnectWise returned invalid or repeated list entries.", 502);
    seen.add(row.id);
    if (row.inactiveFlag || row.inactive || row.deletedFlag || (kind === "statuses" && (row.closedStatus || row.closedFlag))) continue;
    options.push({ id: row.id, name: row.name, ...(typeof row.identifier === "string" ? { identifier: row.identifier } : {}) });
  }
  return { options, more, page };
}
export async function validateCWRouting(connection: ConnectWiseConnection, routing: TicketRouting | Omit<TicketRouting, "companyId">) {
  const refs = { ...("companyId" in routing ? { company: `/company/companies/${routing.companyId}` } : {}), board: `/service/info/boards/${routing.boardId}`,
    ...(routing.teamId ? { team: `/service/boards/${routing.boardId}/teams/${routing.teamId}` } : {}) };
  const entries = await Promise.all(Object.entries(refs).map(async ([name, path]) => {
    const row = await cwRequest(connection, path);
    if (!row || !cwId(row.id) || row.id !== Number(path.split("/").at(-1)) || typeof row.name !== "string" || !row.name.trim() || row.inactiveFlag || row.inactive || row.deletedFlag) throw new DashboardError(`The selected ConnectWise ${name} is unavailable. Reload its list.`);
    return [name, { id: row.id, name: row.name }] as const;
  }));
  return Object.fromEntries(entries) as Record<string, CWOption>;
}
export function ticketUrl(connection: ConnectWiseConnection, id: number): string {
  const url = new URL(connection.endpoint);
  if (/^api-(na|eu|aus)\.myconnectwise\.net$/.test(url.hostname)) url.hostname = url.hostname.slice(4);
  url.pathname = url.pathname.replace(/\/apis\/3\.0$/, "/services/system_io/router/openrecord.rails");
  url.search = new URLSearchParams({ locale: "en_US", companyName: connection.companyId, recordType: "ServiceFv", recid: String(id) }).toString();
  return url.toString();
}
export async function findCWRequest(connection: ConnectWiseConnection, reference: string): Promise<CWRecord | null> {
  if (!/^GMI-(?:GRP-)?[a-f0-9-]{36}$/.test(reference)) throw new DashboardError("Invalid request reference.");
  const rows = await cwRequest(connection, `/service/tickets?${new URLSearchParams({ conditions: `externalXRef="${reference}"`, pageSize: "2" })}`);
  if (!Array.isArray(rows) || rows.length > 1) throw new DashboardError("ConnectWise returned multiple tickets for this request. Review them in ConnectWise before continuing.", 409);
  if (rows[0] && (!cwId(rows[0].id) || rows[0].externalXRef !== reference)) throw new DashboardError("ConnectWise returned an unexpected ticket reference.", 502);
  return rows[0] ?? null;
}
export async function uploadPatchCsv(connection: ConnectWiseConnection, ticketId: number, requestId: string, cve: string, csv: string): Promise<number> {
  const title = `${cve} patch request ${requestId}`;
  // Reconcile before upload so a lost upload response does not duplicate files.
  const docs = await cwRequest(connection, `/system/documents?${new URLSearchParams({ recordType: "Ticket", recordId: String(ticketId), conditions: `title="${title}"`, pageSize: "2" })}`);
  if (!Array.isArray(docs) || docs.length > 1) throw new DashboardError("Unable to reconcile the CSV attachment. Review this ticket's documents.");
  if (docs.length) {
    if (!cwId(docs[0].id) || docs[0].title !== title) throw new DashboardError("ConnectWise returned an unexpected attachment.");
    return docs[0].id;
  }
  const form = new FormData();
  form.append("recordType", "Ticket"); form.append("recordId", String(ticketId)); form.append("title", title);
  form.append("privateFlag", "true");
  form.append("file", new Blob([csv], { type: "text/csv;charset=utf-8" }), `${cve}-patch-request.csv`);
  const doc = await cwRequest(connection, "/system/documents", "POST", form);
  if (!cwId(doc?.id)) throw new CWRequestError("ConnectWise did not confirm the CSV attachment. Retry the attachment check.", true);
  return doc.id;
}
