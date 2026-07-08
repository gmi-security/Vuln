import { NextResponse } from "next/server";
import { ensureHydrated, importFromVulners } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

// Session-gated: enrich all CVE-tagged findings with Vulners intelligence
// (EPSS, exploit availability, CVSS backfill, descriptions).
export async function POST() {
  await ensureHydrated();
  const result = await importFromVulners();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
