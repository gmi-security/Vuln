import { NextResponse } from "next/server";
import { enrichThreatIntel, ensureHydrated } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Token-protected: refresh CISA KEV + live EPSS and re-score every finding.
// Intended for a nightly scheduled job. Requires ?token= or x-admin-token.
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await enrichThreatIntel();
  return NextResponse.json({ result });
}
