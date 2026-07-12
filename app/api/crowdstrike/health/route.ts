import { NextResponse } from "next/server";
import { falconConfig } from "@/lib/crowdstrike";

export const dynamic = "force-dynamic";

// This route is unauthenticated (proxy.ts allowlist) and every reachable
// check performs a real OAuth2 client-credentials grant against CrowdStrike
// with our production secret. Cache the result briefly so an anonymous
// caller hitting this repeatedly can't hammer Falcon's token endpoint /
// trip its own abuse detection on our credentials.
const CACHE_MS = 60_000;
let cached: { body: unknown; status: number; at: number } | null = null;

export async function GET() {
  if (cached && Date.now() - cached.at < CACHE_MS) {
    return NextResponse.json(cached.body, { status: cached.status });
  }

  const config = falconConfig();
  if (!config) {
    const body = {
      configured: false,
      reachable: false,
      status: "Not Configured",
      message: "Set FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, and FALCON_CLOUD.",
    };
    cached = { body, status: 503, at: Date.now() };
    return NextResponse.json(body, { status: 503 });
  }

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
      const body = { configured: true, reachable: false, status: `HTTP ${res.status}`, message: text };
      cached = { body, status: 503, at: Date.now() };
      return NextResponse.json(body, { status: 503 });
    }
    const data: any = await res.json();
    if (!data?.access_token) {
      const body = {
        configured: true,
        reachable: false,
        status: "Auth Failed",
        message: "No access token returned.",
      };
      cached = { body, status: 503, at: Date.now() };
      return NextResponse.json(body, { status: 503 });
    }
    const body = {
      configured: true,
      reachable: true,
      status: "Connected",
      message: `Falcon API reachable (${config.baseUrl}).`,
    };
    cached = { body, status: 200, at: Date.now() };
    return NextResponse.json(body);
  } catch (err) {
    const body = {
      configured: true,
      reachable: false,
      status: "Unreachable",
      message: err instanceof Error ? err.message : "Connection failed.",
    };
    cached = { body, status: 503, at: Date.now() };
    return NextResponse.json(body, { status: 503 });
  }
}
