import { NextResponse } from "next/server";
import { persistenceEnabled, snapshotMeta } from "@/lib/persist";
import { storeStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Public, non-sensitive health/persistence status (counts only). Used to
// verify the snapshot round-trip survives redeploys.
export async function GET() {
  const [status, meta] = await Promise.all([storeStatus(), snapshotMeta()]);
  return NextResponse.json({
    persistence: {
      enabled: persistenceEnabled(),
      snapshotUpdatedAt: meta.updatedAt,
    },
    ...status,
  });
}
