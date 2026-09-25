import { NextResponse } from "next/server";
import { falconConfigs, type FalconTenant } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// This route is unauthenticated (proxy.ts allowlist) and every reachable
// check performs a real OAuth2 client-credentials grant against CrowdStrike
// with our production secret(s). Cache the result briefly so an anonymous
// caller hitting this repeatedly can't hammer Falcon's token endpoint /
// trip its own abuse detection on our credentials.
const CACHE_MS = 60_000;
let cached: { body: unknown; status: number; at: number } | null = null;

async function probeTenant(config: FalconTenant) {
  const label = config.customerName ?? config.label;
  try {
    const res = await fetch(`${config.baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      return { label, reachable: false, status: `HTTP ${res.status}`, message: text };
    }
    const data: any = await res.json();
    if (!data?.access_token) {
      return { label, reachable: false, status: "Auth Failed", message: "No access token returned." };
    }
    return { label, reachable: true, status: "Connected", message: `Falcon API reachable (${config.baseUrl}).` };
  } catch (err) {
    return {
      label,
      reachable: false,
      status: "Unreachable",
      message: err instanceof Error ? err.message : "Connection failed.",
    };
  }
}

export async function GET() {
  if (cached && Date.now() - cached.at < CACHE_MS) {
    return NextResponse.json(cached.body, { status: cached.status });
  }

  const configs = falconConfigs();
  if (!configs.length) {
    const body = {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD.",
    };
    cached = { body, status: 503, at: Date.now() };
    return NextResponse.json(body, { status: 503 });
  }

  const tenants = await Promise.all(configs.map(probeTenant));
  const allReachable = tenants.every((t) => t.reachable);
  const body = {
    configured: true,
    reachable: allReachable,
    status: allReachable ? "Connected" : "Degraded",
    message: allReachable
      ? tenants.length > 1
        ? `All ${tenants.length} CrowdStrike tenants reachable.`
        : tenants[0].message
      : `${tenants.filter((t) => !t.reachable).length} of ${tenants.length} CrowdStrike tenant(s) unreachable.`,
    tenants: tenants.length > 1 ? tenants : undefined,
  };
  cached = { body, status: allReachable ? 200 : 503, at: Date.now() };
  return NextResponse.json(body, { status: allReachable ? 200 : 503 });
}
