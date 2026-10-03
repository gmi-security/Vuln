import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { falconConfigs, type FalconTenant } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// This route is unauthenticated (proxy.ts allowlist) and every reachable
// check performs a real OAuth2 client-credentials grant against CrowdStrike
// with our production secret(s). Cache the result briefly so an anonymous
// caller hitting this repeatedly can't hammer Falcon's token endpoint /
// trip its own abuse detection on our credentials.
//
// The cache holds only the raw per-tenant probe results, never a
// request-specific response body -- the public/authenticated split below
// is computed fresh every request so an anonymous caller can never be
// served a cached authenticated response.
const CACHE_MS = 60_000;
let cached: { tenants: Awaited<ReturnType<typeof probeTenant>>[] | null; at: number } | null = null;

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
  // Per-tenant customerName/label (the MSP's real client names, from
  // FALCON_CUSTOMER_N) and raw vendor error text are only for a signed-in
  // caller -- an anonymous request gets the same aggregate-only shape every
  // other connector health route (nessus/spiderfoot/artemis/burp/nmap/zap)
  // already uses.
  const session = await getServerSession(authOptions);
  const authed = Boolean(session?.user);

  let tenants: Awaited<ReturnType<typeof probeTenant>>[] | null;
  if (cached && Date.now() - cached.at < CACHE_MS) {
    tenants = cached.tenants;
  } else {
    const configs = falconConfigs();
    tenants = configs.length ? await Promise.all(configs.map(probeTenant)) : null;
    cached = { tenants, at: Date.now() };
  }

  if (!tenants) {
    const body = {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD.",
    };
    return NextResponse.json(body, { status: 503 });
  }

  const allReachable = tenants.every((t) => t.reachable);
  const unreachableCount = tenants.filter((t) => !t.reachable).length;
  const body = authed
    ? {
        configured: true,
        reachable: allReachable,
        status: allReachable ? "Connected" : "Degraded",
        message: allReachable
          ? tenants.length > 1
            ? `All ${tenants.length} CrowdStrike tenants reachable.`
            : tenants[0].message
          : `${unreachableCount} of ${tenants.length} CrowdStrike tenant(s) unreachable.`,
        tenants: tenants.length > 1 ? tenants : undefined,
      }
    : {
        configured: true,
        reachable: allReachable,
        status: allReachable ? "Connected" : "Degraded",
        message: allReachable ? "CrowdStrike reachable." : `${unreachableCount} of ${tenants.length} CrowdStrike tenant(s) unreachable.`,
      };
  return NextResponse.json(body, { status: allReachable ? 200 : 503 });
}
