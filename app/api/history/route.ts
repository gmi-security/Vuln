import { NextResponse } from "next/server";
import { ensureHydrated } from "@/lib/store";
import { loadMetricsHistory } from "@/lib/persist";

export const dynamic = "force-dynamic";

const DEFAULT_DAYS = 90;
const MAX_DAYS = 365;

// Metrics history time series for trend charts. companyId scopes to one
// company; omit it for the global (all-customer) series. Rows are appended
// after every sync-all and at least once per UTC day by the scheduler.
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") || null;
  const daysParam = Number.parseInt(searchParams.get("days") ?? "", 10);
  const days = Number.isFinite(daysParam)
    ? Math.min(Math.max(daysParam, 1), MAX_DAYS)
    : DEFAULT_DAYS;

  const rows = await loadMetricsHistory(companyId, days);
  return NextResponse.json({
    snapshots: rows.map((row) => ({
      ts: row.ts,
      companyId,
      ...(row.data as Record<string, unknown>),
    })),
  });
}
