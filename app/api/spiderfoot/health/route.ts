import { NextResponse } from "next/server";
import { spiderfootStatus } from "@/lib/spiderfoot";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Reachability probe — returns only server liveness + scan count, no scan
// data, so it is safe to expose for diagnostics. Cached briefly since this
// is unauthenticated and probes a real appliance.
export async function GET() {
  const { body, status } = await cachedHealth("spiderfoot", 30_000, async () => ({
    body: await spiderfootStatus(),
  }));
  return NextResponse.json(body, { status });
}
