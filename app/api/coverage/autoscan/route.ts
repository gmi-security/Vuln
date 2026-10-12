import { withDurablePlatformMutation } from "@/lib/platform-mutation-route";
import { NextResponse } from "next/server";
import { autoScanGaps, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// Launch scans for all known-but-unscanned assets (the coverage gap).
async function POSTHandler() {
  try {
    await ensureHydrated();
    const result = await autoScanGaps();
    return NextResponse.json({ result });
  } catch (err) {
    console.error("[coverage/autoscan]", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Auto-scan failed." },
      { status: 502 },
    );
  }
}

export const POST = withDurablePlatformMutation(POSTHandler);
