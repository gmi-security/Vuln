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
  return NextResponse.json({ coverage });
}
