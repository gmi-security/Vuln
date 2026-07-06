import { NextResponse } from "next/server";
import { ensureHydrated, launchOsintScans } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// Token-protected quarterly automation: launches Artemis + SpiderFoot OSINT
// scans for every client company. Intended to be hit by a scheduled job
// (GitHub Action / DO scheduled job). Requires ?token= or an x-admin-token
// header matching ADMIN_TOKEN.
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await launchOsintScans();
  return NextResponse.json({ result });
}
