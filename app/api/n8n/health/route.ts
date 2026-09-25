import { NextResponse } from "next/server";
import { n8nStatus } from "@/lib/n8n";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Reachability probe — returns only configuration + liveness, no workflow
// data, so it is safe to expose for diagnostics. Cached briefly since this
// is unauthenticated and probes a real endpoint.
export async function GET() {
  const { body, status } = await cachedHealth("n8n", 30_000, async () => ({
    body: await n8nStatus(),
  }));
  return NextResponse.json(body, { status });
}
