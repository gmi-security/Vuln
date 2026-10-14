import { withDurablePlatformMutation } from "@/lib/platform-mutation-route";
import { NextResponse } from "next/server";
import { ensureHydrated, startCsDevicesSync, getCsDevicesSyncStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

async function POSTHandler() {
  await ensureHydrated();
  const launch = startCsDevicesSync();
  if (!launch.started && launch.error) {
    return NextResponse.json({ error: launch.error }, { status: 400 });
  }
  return NextResponse.json({ status: getCsDevicesSyncStatus() });
}

export async function GET() {
  return NextResponse.json({ status: getCsDevicesSyncStatus() });
}

export const POST = withDurablePlatformMutation(POSTHandler);
