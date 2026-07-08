import { NextResponse } from "next/server";
import { ensureHydrated, syncAllConnectors, enrichThreatIntel } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 600;

// Session-gated: pull results from every configured connector in series, then
// run threat-intel enrichment so KEV/EPSS/ransomware flags apply immediately.
export async function POST() {
  try {
    await ensureHydrated();
    const results = await syncAllConnectors();
    let enrich: Record<string, unknown> | null = null;
    if (results.some((r) => r.ok)) {
      try {
        enrich = await enrichThreatIntel() as Record<string, unknown>;
      } catch {
        // enrichment failure doesn't fail the whole sync
      }
    }
    return NextResponse.json({ results, enrich });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Sync-all failed." },
      { status: 502 },
    );
  }
}
