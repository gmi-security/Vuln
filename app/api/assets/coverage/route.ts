import { NextResponse } from "next/server";
import { assetCoverage, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// Diff of known assets (inventory) vs scanned assets (seen in findings).
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ coverage: assetCoverage({ companyId }) });
}
