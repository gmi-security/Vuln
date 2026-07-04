import { NextResponse } from "next/server";
import { computeAttackPaths, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// Blast-radius / attack-path model: internet-facing exploitable entry points
// and the high-value assets they can reach.
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ attackPaths: computeAttackPaths({ companyId }) });
}
