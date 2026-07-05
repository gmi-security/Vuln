import { NextResponse } from "next/server";
import { spiderfootConfig, spiderfootListScans } from "@/lib/spiderfoot";

export const dynamic = "force-dynamic";

// List the scans available on the configured SpiderFoot server.
export async function GET() {
  if (!spiderfootConfig()) {
    return NextResponse.json(
      { error: "SpiderFoot is not configured. Set SPIDERFOOT_URL." },
      { status: 400 },
    );
  }
  try {
    return NextResponse.json({ scans: await spiderfootListScans() });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to reach SpiderFoot." },
      { status: 502 },
    );
  }
}
