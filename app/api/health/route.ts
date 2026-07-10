import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { persistenceEnabled, pingDb, snapshotMeta } from "@/lib/persist";
import { storeStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Allow-listed in proxy.ts, so anonymous callers can reach this route. They
// only get a liveness bit; error text, tenant counts, and snapshot metadata
// are reserved for signed-in sessions.
export async function GET(request: NextRequest) {
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  const ping = await pingDb();
  if (!token) {
    return NextResponse.json({
      ok: true,
      persistence: {
        enabled: persistenceEnabled(),
        dbReachable: ping.ok,
      },
    });
  }

  const [status, meta] = await Promise.all([storeStatus(), snapshotMeta()]);
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
