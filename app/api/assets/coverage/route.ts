import { NextResponse } from "next/server";
import { assetCoverageWithSpotlight, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// Diff of known assets (inventory) vs scanned assets (seen in results),
// merged with CrowdStrike Spotlight's per-host coverage (finding_risk/
// Postgres never touches the legacy in-memory store on its own).
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  const coverage = await assetCoverageWithSpotlight({ companyId });
  if (companyId) {
    // Temporary diagnostic: which import actually populated "known assets"
    // for this company -- tidal (live sync), manual (CSV/manual entry), or
    // crowdstrike (device endpoint sync). Remove once answered.
    const bySource = new Map<string, number>();
    for (const row of [...coverage.matched, ...coverage.knownNotScanned]) {
      const key = row.source ?? "(null)";
      bySource.set(key, (bySource.get(key) ?? 0) + 1);
    }
    console.error(`[coverage-source-debug] ${companyId}:`, Object.fromEntries(bySource));
  }
  return NextResponse.json({ coverage });
}
