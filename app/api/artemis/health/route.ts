import { NextResponse } from "next/server";
import { artemisStatus } from "@/lib/artemis";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Reachability + token-validity probe (no scan data). Cached briefly since
// this is unauthenticated and probes a real appliance.
export async function GET() {
  const { body, status } = await cachedHealth("artemis", 30_000, async () => ({
    body: await artemisStatus(),
  }));
  return NextResponse.json(body, { status });
}
