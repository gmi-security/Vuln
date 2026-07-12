import { NextResponse } from "next/server";
import { nmapStatus } from "@/lib/nmap";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Reachability probe — returns only configuration + liveness, no scan data,
// so it is safe to expose for diagnostics. Cached briefly since this is
// unauthenticated and probes a real appliance.
export async function GET() {
  const { body, status } = await cachedHealth("nmap", 30_000, async () => ({
    body: await nmapStatus(),
  }));
  return NextResponse.json(body, { status });
}
