import { NextResponse } from "next/server";
import { ensureHydrated, launchOsintScans } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated (via the edge proxy): launch supplemental OSINT scans
// (Artemis + SpiderFoot) for all client companies. Triggered by the
// "Run OSINT scans" button.
export async function POST() {
  try {
    await ensureHydrated();
    const result = await launchOsintScans();
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "OSINT launch failed." },
      { status: 502 },
    );
  }
}
