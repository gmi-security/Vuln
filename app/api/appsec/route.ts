import { NextResponse } from "next/server";
import { appsecElasticConfig, fetchAppSecSummary, fetchAppSecTrend } from "@/lib/elastic-appsec";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET() {
  if (!appsecElasticConfig()) {
    return NextResponse.json({ configured: false, summary: null, trend: null });
  }
  try {
    const summary = await fetchAppSecSummary();
    // The trend chart is a secondary view on the same page -- a failure
    // fetching it must not take down the summary tiles/table above it.
    const trend = await fetchAppSecTrend().catch(() => null);
    return NextResponse.json({ configured: true, summary, trend });
  } catch (err) {
    const message = err instanceof DashboardError ? err.message : "Could not reach the AppSec Elastic index.";
    return NextResponse.json({ configured: true, summary: null, trend: null, error: message }, { status: 502 });
  }
}
