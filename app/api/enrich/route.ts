import { NextResponse } from "next/server";
import { enrichThreatIntel, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Session-gated (via the edge proxy): refresh CISA KEV + live EPSS and re-score
// every finding. Triggered by the "Refresh threat intel" button. No admin
// token — a logged-in user runs it on demand.
export async function POST() {
  try {
    await ensureHydrated();
    const result = await enrichThreatIntel();
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Enrichment failed." },
      { status: 502 },
    );
  }
}
