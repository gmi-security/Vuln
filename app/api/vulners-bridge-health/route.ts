import { NextResponse } from "next/server";
import { vulnersStatus } from "@/lib/vulners";
import { cachedHealth } from "@/lib/health-cache";

export const dynamic = "force-dynamic";

// Cached briefly since this is unauthenticated and probes a real bridge/API.
export async function GET() {
  const { body, status } = await cachedHealth("vulners", 30_000, async () => {
    const s = await vulnersStatus();
    return { body: s, status: s.reachable ? 200 : 503 };
  });
  return NextResponse.json(body, { status });
}
