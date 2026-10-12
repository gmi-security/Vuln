import { NextResponse } from "next/server";
import { computeExecReport, ensureHydrated } from "@/lib/store";
import { loadMetricsHistory, loadLegacyCustomerMetricsHistory } from "@/lib/persist";
import { savedReportingExecutive } from "@/lib/reporting-saved-overview";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ companyId: string }> },
) {
  const { companyId } = await params;
  try {
    const saved = await savedReportingExecutive(companyId);
    if (saved) return NextResponse.json(saved, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return NextResponse.json({ error: error instanceof DashboardError ? error.message : "Saved report unavailable." },
      { status: error instanceof DashboardError ? error.status : 503, headers: { "cache-control": "no-store" } });
  }
  await ensureHydrated();
  const report = computeExecReport(companyId);
  if (!report) {
    return NextResponse.json({ error: "Company not found." }, { status: 404 });
  }
  report.generatedAt = new Date().toISOString();
  // Last 180 days of this company's metrics history (same row shape as
  // /api/history). Fail-safe: [] when the DB is unset/unreachable.
  const [history, legacyHistory] = await Promise.all([
    loadMetricsHistory(companyId, 180), loadLegacyCustomerMetricsHistory(companyId),
  ]);
  const trend = history.map((row) => ({
    ts: row.ts,
    companyId,
    ...(row.data as Record<string, unknown>),
  }));
  return NextResponse.json({ report: { ...report, trend,
    legacyTrend: legacyHistory.map(row => ({ ts: row.ts, sourceCompanyId: row.sourceCompanyId,
      sourceCompanyName: row.sourceCompanyName, ...row.data as Record<string, unknown> })) } });
}
