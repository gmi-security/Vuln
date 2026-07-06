import { NextResponse } from "next/server";
import { ensureHydrated, getTidalSyncStatus, startTidalSync } from "@/lib/store";

export const dynamic = "force-dynamic";

// Start a background Tidal sync. The live sync spans ~49 client companies and
// can pull thousands of devices, so it runs in the background — POST kicks it
// off and returns immediately; poll GET for progress.
export async function POST() {
  await ensureHydrated();
  const { started, error } = startTidalSync();
  if (!started) {
    const status = getTidalSyncStatus();
    // Already running -> report the live status (not an error).
    if (status.running) return NextResponse.json({ started: false, status });
    return NextResponse.json({ error }, { status: 400 });
  }
  return NextResponse.json({ started: true, status: getTidalSyncStatus() });
}

// Poll the current sync status/progress.
export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ status: getTidalSyncStatus() });
}
