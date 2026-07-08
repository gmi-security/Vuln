import { NextResponse } from "next/server";
import { ensureHydrated, importFromCrowdstrikeSpotlight } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Pull CrowdStrike Falcon Spotlight open vulnerabilities as vuln-class findings.
// Requires FALCON_CLIENT_ID / FALCON_CLIENT_SECRET / FALCON_CLOUD and the
// spotlight-vulnerabilities:read scope on the API client.
export async function POST() {
  await ensureHydrated();
  const result = await importFromCrowdstrikeSpotlight();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
