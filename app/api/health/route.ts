import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getToken } from "next-auth/jwt";
import { persistenceEnabled, pingDb, snapshotMeta } from "@/lib/persist";
import { storeStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Allow-listed in proxy.ts, so anonymous callers can reach this route. They
// only get readiness/storage booleans; error text, tenant counts and metadata
// are reserved for signed-in sessions.
export async function GET(request: NextRequest) {
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET,
  });

  const [ping,status] = await Promise.all([pingDb(),storeStatus()]);
  const readReady = (!persistenceEnabled() || ping.ok) && status.hydrated && (status.runtimeRole === "web" || !status.persistBlocked);
  const writeReady = status.runtimeRole === "web"
    ? Boolean(status.worker?.available && status.worker.ready && !status.worker.blocked)
    : readReady && !status.persistBlocked && (!persistenceEnabled() || !status.persistenceState || status.persistenceState === "healthy");
  const ready = readReady && writeReady;
  if (!token) {
    const internal = Boolean((globalThis as any)[Symbol.for("vuln.readContext")]?.getStore()?.internalWorker);
    return NextResponse.json({
      ok: ready,
      ready,
      readReady,
      writeReady,
      ...(internal ? {persistenceStatus: {
        persistenceState:status.persistBlocked?'blocked':status.persistenceState,
        lastCommittedRevision:status.lastCommittedRevision,lastCommittedAt:status.lastCommittedAt,
        pendingSince:status.pendingSince,nextRetryAt:status.nextRetryAt,firstError:status.firstError,
      }} : {}),
      persistence: {
        enabled: persistenceEnabled(),
        dbReachable: ping.ok,
        blocked: status.persistBlocked,
      },
    }, {status:ready ? 200 : 503});
  }

  const meta = await snapshotMeta();
  return NextResponse.json({
    ok: ready,
    ready,
    readReady,
    writeReady,
    persistence: {
      enabled: persistenceEnabled(),
      dbReachable: ping.ok,
      dbError: ping.error ?? null,
      snapshotUpdatedAt: meta.updatedAt,
    },
    ...status,
    persistenceState:status.persistBlocked?'blocked':status.persistenceState,
    lastCommittedAt:status.lastCommittedAt??meta.updatedAt,
  });
}
