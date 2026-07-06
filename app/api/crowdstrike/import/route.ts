import { NextResponse } from "next/server";
import { ensureHydrated, importFromCrowdstrike } from "@/lib/store";

export const dynamic = "force-dynamic";

// Sync CrowdStrike Falcon host inventory into the internal org's assets.
export async function POST() {
  try {
    await ensureHydrated();
    const result = await importFromCrowdstrike();
    if ("error" in result) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "CrowdStrike import failed." },
      { status: 502 },
    );
  }
}
