import { NextResponse } from "next/server";
import { autoScanGaps, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// Launch scans for all known-but-unscanned assets (the coverage gap).
export async function POST() {
  try {
    await ensureHydrated();
    const result = await autoScanGaps();
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Auto-scan failed." },
      { status: 502 },
    );
  }
}
