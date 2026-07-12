import { NextResponse } from "next/server";
import { burpStatus } from "@/lib/burp";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Reachability probe — returns only configuration + liveness, no issue data,
// so it is safe to expose for diagnostics. Cached briefly since this is
// unauthenticated and probes a real appliance.
export async function GET() {
  const { body, status } = await cachedHealth("burp", 30_000, async () => ({
    body: await burpStatus(),
  }));
  return NextResponse.json(body, { status });
}
