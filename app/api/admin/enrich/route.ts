import { NextResponse } from "next/server";
import { enrichThreatIntel, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Token-protected: refresh CISA KEV + live EPSS and re-score every finding.
// Intended for a nightly scheduled job. Requires ?token= or x-admin-token.
export async function POST(request: Request) {
  const token =
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    "";
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await enrichThreatIntel();
  return NextResponse.json({ result });
}
