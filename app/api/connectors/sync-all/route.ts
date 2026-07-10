import { NextResponse } from "next/server";
import { ensureHydrated, startSyncAll, syncAllStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated: pull results from every configured connector in series, then
// run threat-intel enrichment so KEV/EPSS/ransomware flags apply immediately.
// The full sweep can take minutes, so it runs as a background job — POST kicks
// it off and returns immediately; poll GET for the results.
export async function POST() {
  await ensureHydrated();
  const { started } = startSyncAll();
  if (!started) {
    // Already running -> report the live status (not an error).
    return NextResponse.json(
      { alreadyRunning: true, status: syncAllStatus() },
      { status: 202 },
    );
  }
  return NextResponse.json({ started: true, status: syncAllStatus() }, { status: 202 });
}

// Poll the current sync-all status.
export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ status: syncAllStatus() });
}
