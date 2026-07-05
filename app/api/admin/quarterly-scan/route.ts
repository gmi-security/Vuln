import { NextResponse } from "next/server";
import { ensureHydrated, launchOsintScans } from "@/lib/store";

export const dynamic = "force-dynamic";

// Token-protected quarterly automation: launches Artemis + SpiderFoot OSINT
// scans for every client company. Intended to be hit by a scheduled job
// (GitHub Action / DO scheduled job). Requires ?token= or an x-admin-token
// header matching ADMIN_TOKEN.
export async function POST(request: Request) {
  const token =
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    "";
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await launchOsintScans();
  return NextResponse.json({ result });
}
