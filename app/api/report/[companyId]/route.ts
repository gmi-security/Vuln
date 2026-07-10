import { NextResponse } from "next/server";
import { computeExecReport, ensureHydrated } from "@/lib/store";
import { loadMetricsHistory } from "@/lib/persist";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ companyId: string }> },
) {
  await ensureHydrated();
  const { companyId } = await params;
  const report = computeExecReport(companyId);
  if (!report) {
    return NextResponse.json({ error: "Company not found." }, { status: 404 });
  }
  report.generatedAt = new Date().toISOString();
  // Last 180 days of this company's metrics history (same row shape as
  // /api/history). Fail-safe: [] when the DB is unset/unreachable.
  const history = await loadMetricsHistory(companyId, 180);
  const trend = history.map((row) => ({
    ts: row.ts,
    companyId,
    ...(row.data as Record<string, unknown>),
  }));
  return NextResponse.json({ report: { ...report, trend } });
}
