import { withDurablePlatformMutation } from "@/lib/platform-mutation-route";
import { NextResponse } from "next/server";
import { ensureHydrated, startAutomateSync, getAutomateSyncStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

async function POSTHandler() {
  await ensureHydrated();
  const launch = startAutomateSync();
  if (!launch.started && launch.error) {
    return NextResponse.json({ error: launch.error }, { status: 400 });
  }
  return NextResponse.json({ status: getAutomateSyncStatus() });
}

export async function GET() {
  return NextResponse.json({ status: getAutomateSyncStatus() });
}

export const POST = withDurablePlatformMutation(POSTHandler);
