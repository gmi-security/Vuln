import { NextResponse } from "next/server";
import { persistenceEnabled, pingDb, snapshotMeta } from "@/lib/persist";
import { storeStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  const [status, meta, ping] = await Promise.all([
    storeStatus(),
    snapshotMeta(),
    pingDb(),
  ]);
  return NextResponse.json({
    persistence: {
      enabled: persistenceEnabled(),
      dbReachable: ping.ok,
      dbError: ping.error ?? null,
      snapshotUpdatedAt: meta.updatedAt,
    },
    ...status,
  });
}
