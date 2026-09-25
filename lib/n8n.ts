// n8n adapter — a generic pipe into a workflow hosted on the GMI n8n
// instance, for data sources that don't have (or don't yet need) a
// dedicated connector of their own. Point it at one workflow's
// webhook-trigger production URL; that workflow decides what data comes
// back. No data mapping lives here yet — n8nCallWorkflow() just returns
// the raw JSON body until a specific source and shape are decided.
//
//   N8N_WEBHOOK_URL   full production webhook URL of the target workflow
//                      (e.g. https://n8n.gmi.com/webhook/<path>)
//   N8N_API_KEY       optional — sent as X-N8N-API-KEY if the workflow's
//                      webhook node requires header auth

export type N8nConfig = { webhookUrl: string; apiKey: string | null };

export function n8nConfig(): N8nConfig | null {
  const webhookUrl = process.env.N8N_WEBHOOK_URL?.trim();
  if (!webhookUrl) return null;
  return {
    webhookUrl: webhookUrl.replace(/\/+$/, ""),
    apiKey: process.env.N8N_API_KEY?.trim() || null,
  };
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

export async function n8nStatus(): Promise<{
  configured: boolean;
  reachable: boolean;
  status: string;
  message: string;
}> {
  const config = n8nConfig();
  if (!config) {
    return {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set N8N_WEBHOOK_URL to a workflow's production webhook URL (optionally N8N_API_KEY).",
    };
  }
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
      configured: true,
      reachable,
      status: reachable ? "Connected" : `HTTP ${res.status}`,
      message: reachable
        ? "n8n workflow endpoint reachable."
        : await res.text().catch(() => res.statusText),
    };
  } catch (err) {
    return {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: describeFetchError(err),
    };
  }
}

// Generic call-through for whichever workflow ends up wired to this
// connector. No shape/mapping assumptions — callers decide what to do with
// the JSON that comes back.
export async function n8nCallWorkflow(body?: unknown): Promise<any> {
  const config = n8nConfig();
  if (!config) throw new Error("n8n is not configured.");
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
