// n8n adapter — a generic pipe into a workflow hosted on the GMI n8n
// instance, for data sources that don't have (or don't yet need) a
// dedicated connector of their own. Two independent transports, either
// (or both) of which is enough to be "configured":
//
//   N8N_WEBHOOK_URL   a workflow's production Webhook-trigger URL, called
//                      as plain HTTP (e.g. https://n8n.gmi.com/webhook/<path>)
//   N8N_API_KEY       optional — sent as X-N8N-API-KEY on webhook calls, if
//                      that trigger node requires header auth
//
//   N8N_MCP_URL        a workflow's MCP-trigger URL, called over the MCP
//                      "Streamable HTTP" transport (JSON-RPC 2.0)
//                      (e.g. https://n8n.gmi.com/mcp/<id>)
//
// No data mapping lives here yet — n8nCallWorkflow() / n8nMcpCallTool()
// just return the raw response until a specific source and shape are
// decided.

export type N8nConfig = { webhookUrl: string; apiKey: string | null };

export function n8nConfig(): N8nConfig | null {
  const webhookUrl = process.env.N8N_WEBHOOK_URL?.trim();
  if (!webhookUrl) return null;
  return {
    webhookUrl: webhookUrl.replace(/\/+$/, ""),
    apiKey: process.env.N8N_API_KEY?.trim() || null,
  };
}

export type N8nMcpConfig = { url: string };

export function n8nMcpConfig(): N8nMcpConfig | null {
  const url = process.env.N8N_MCP_URL?.trim();
  if (!url) return null;
  return { url };
}

// Node's fetch() throws a generic "fetch failed" TypeError for DNS/connect
// failures and buries the actual reason in `.cause` — surface that instead.
function describeFetchError(err: unknown): string {
  if (err instanceof Error) {
    const cause = (err as { cause?: unknown }).cause;
    if (err.name === "AbortError" || err.name === "TimeoutError") return "Request timed out.";
    if (cause instanceof Error) return cause.message;
    if (typeof cause === "string") return cause;
    return err.message;
  }
  return "Connection failed.";
}

type TransportStatus = { reachable: boolean; status: string; message: string };

async function probeWebhook(config: N8nConfig): Promise<TransportStatus> {
  try {
    const res = await fetch(config.webhookUrl, {
      method: "GET",
      headers: config.apiKey ? { "X-N8N-API-KEY": config.apiKey } : undefined,
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    // A webhook wired for POST-only still proves the route exists on a
    // 404/405 — only a 5xx or connection failure means it's actually down.
    const reachable = res.status < 500;
    return {
      reachable,
      status: reachable ? "Connected" : `HTTP ${res.status}`,
      message: reachable
        ? "Webhook endpoint reachable."
        : await res.text().catch(() => res.statusText),
    };
  } catch (err) {
    return { reachable: false, status: "Unreachable", message: describeFetchError(err) };
  }
}

// Generic call-through for whichever workflow ends up wired to this
// connector. No shape/mapping assumptions — callers decide what to do with
// the JSON that comes back.
export async function n8nCallWorkflow(body?: unknown): Promise<any> {
  const config = n8nConfig();
  if (!config) throw new Error("n8n webhook is not configured.");
  const res = await fetch(config.webhookUrl, {
    method: body ? "POST" : "GET",
    headers: {
      ...(config.apiKey ? { "X-N8N-API-KEY": config.apiKey } : {}),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    throw new Error(
      `n8n workflow call HTTP ${res.status}: ${await res.text().catch(() => res.statusText)}`,
    );
  }
  return res.json();
}

// --- MCP (Model Context Protocol) transport ---------------------------------
// Talks to the MCP Trigger node directly over the "Streamable HTTP"
// transport: JSON-RPC 2.0 messages POSTed to one URL, tracked by an
// Mcp-Session-Id header handed back from `initialize`.

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id?: number | string;
  result?: any;
  error?: { code: number; message: string };
};

// The transport may answer with a plain JSON body or an SSE stream
// ("event: message\ndata: {...}\n\n") carrying one JSON-RPC message — read
// whichever comes back.
async function readMcpResponse(res: Response): Promise<JsonRpcResponse | null> {
  const contentType = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (!text) return null;
  if (contentType.includes("text/event-stream")) {
    for (const line of text.split("\n")) {
      if (line.startsWith("data:")) {
        try {
          return JSON.parse(line.slice(5).trim());
        } catch {
          continue;
        }
      }
    }
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function mcpRequest(
  cfg: N8nMcpConfig,
  method: string,
  params: unknown,
  sessionId: string | null,
  id: number | null,
  timeoutMs = 15_000,
): Promise<{ response: JsonRpcResponse | null; sessionId: string | null; res: Response }> {
  const body: Record<string, unknown> = { jsonrpc: "2.0", method, params };
  if (id !== null) body.id = id;
  const res = await fetch(cfg.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
    },
    body: JSON.stringify(body),
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
  });
  const newSessionId = res.headers.get("mcp-session-id") ?? sessionId;
  // Notifications (id === null) get a 202 with no body — nothing to parse.
  const response = id !== null ? await readMcpResponse(res) : null;
  return { response, sessionId: newSessionId, res };
}

async function mcpOpenSession(cfg: N8nMcpConfig): Promise<string> {
  const { response, sessionId, res } = await mcpRequest(
    cfg,
    "initialize",
    {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "gmi-vuln", version: "1.0" },
    },
    null,
    1,
  );
  if (!res.ok) throw new Error(`MCP initialize HTTP ${res.status}: ${res.statusText}`);
  if (response?.error) throw new Error(`MCP initialize error: ${response.error.message}`);
  if (!sessionId) throw new Error("MCP server did not return a session id.");
  await mcpRequest(cfg, "notifications/initialized", {}, sessionId, null);
  return sessionId;
}

async function mcpCloseSession(cfg: N8nMcpConfig, sessionId: string): Promise<void> {
  await fetch(cfg.url, {
    method: "DELETE",
    headers: { "Mcp-Session-Id": sessionId },
    signal: AbortSignal.timeout(10_000),
  }).catch(() => undefined);
}

async function probeMcp(cfg: N8nMcpConfig): Promise<TransportStatus> {
  let sessionId: string | null = null;
  try {
    sessionId = await mcpOpenSession(cfg);
    return { reachable: true, status: "Connected", message: "MCP endpoint reachable." };
  } catch (err) {
    return { reachable: false, status: "Unreachable", message: describeFetchError(err) };
  } finally {
    if (sessionId) await mcpCloseSession(cfg, sessionId);
  }
}

// Generic tool discovery/call for whatever this MCP server exposes — no
// assumptions about specific tools yet. Opens and closes its own session.
export async function n8nMcpListTools(): Promise<any[]> {
  const cfg = n8nMcpConfig();
  if (!cfg) throw new Error("n8n MCP is not configured.");
  const sessionId = await mcpOpenSession(cfg);
  try {
    const { response, res } = await mcpRequest(cfg, "tools/list", {}, sessionId, 2);
    if (!res.ok) throw new Error(`MCP tools/list HTTP ${res.status}`);
    if (response?.error) throw new Error(`MCP tools/list error: ${response.error.message}`);
    return response?.result?.tools ?? [];
  } finally {
    await mcpCloseSession(cfg, sessionId);
  }
}

export async function n8nMcpCallTool(name: string, args: Record<string, unknown> = {}): Promise<any> {
  const cfg = n8nMcpConfig();
  if (!cfg) throw new Error("n8n MCP is not configured.");
  const sessionId = await mcpOpenSession(cfg);
  try {
    const { response, res } = await mcpRequest(
      cfg,
      "tools/call",
      { name, arguments: args },
      sessionId,
      3,
      30_000,
    );
    if (!res.ok) throw new Error(`MCP tools/call HTTP ${res.status}`);
    if (response?.error) throw new Error(`MCP tools/call error: ${response.error.message}`);
    return response?.result;
  } finally {
    await mcpCloseSession(cfg, sessionId);
  }
}

// --- Combined reachability -------------------------------------------------
// Probes whichever transport(s) are configured and reports both.
export async function n8nStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
  transports?: { webhook?: TransportStatus; mcp?: TransportStatus };
}> {
  const webhookCfg = n8nConfig();
  const mcpCfg = n8nMcpConfig();
  if (!webhookCfg && !mcpCfg) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set N8N_WEBHOOK_URL and/or N8N_MCP_URL.",
    };
  }
  const transports: { webhook?: TransportStatus; mcp?: TransportStatus } = {};
  if (webhookCfg) transports.webhook = await probeWebhook(webhookCfg);
  if (mcpCfg) transports.mcp = await probeMcp(mcpCfg);
  const reachable = Object.values(transports).some((t) => t.reachable);
  return {
    configured: true,
    reachable,
    status: reachable ? "Connected" : "Unreachable",
    message: Object.entries(transports)
      .map(([k, v]) => `${k}: ${v.status}`)
      .join(" · "),
    transports,
  };
}
