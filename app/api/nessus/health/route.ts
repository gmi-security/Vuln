import { NextResponse } from "next/server";
import { nessusServerStatus } from "@/lib/nessus";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Connectivity/activation probe. Returns only scanner reachability + status
// (no credentials or scan data), so it is safe to expose for diagnostics.
// Cached briefly since this is unauthenticated and probes a real appliance.
export async function GET() {
  const { body, status } = await cachedHealth("nessus", 30_000, async () => ({
    body: await nessusServerStatus(),
  }));
  return NextResponse.json(body, { status });
}
