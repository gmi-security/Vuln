import { NextResponse } from "next/server";
import { ensureHydrated, importFromNmap } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Live pull from an Nmap scan-runner. Session-gated via the edge proxy.
// Returns 400 with guidance when NMAP_RUNNER_URL/NMAP_RUNNER_TOKEN are unset —
// use the XML upload route in that case.
export async function POST() {
  await ensureHydrated();
  const result = await importFromNmap();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
