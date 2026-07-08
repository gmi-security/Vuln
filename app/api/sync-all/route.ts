import { NextResponse } from "next/server";
import { ensureHydrated, syncAllConnectors, enrichThreatIntel } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 600;

// Fan out all configured connectors in series, then run threat-intel enrichment.
// Returns a per-connector status array plus the enrichment summary so the UI
// can show exactly what populated and what was skipped.
export async function POST() {
  await ensureHydrated();

  const connectors = await syncAllConnectors();
  const anyOk = connectors.some((c) => c.ok);

  let enrich: Awaited<ReturnType<typeof enrichThreatIntel>> | null = null;
  if (anyOk) {
    try {
      enrich = await enrichThreatIntel();
    } catch {
      // enrichment failure shouldn't fail the whole sync
    }
  }

  return NextResponse.json({ connectors, enrich });
}
