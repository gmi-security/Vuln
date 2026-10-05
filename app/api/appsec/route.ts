import { NextResponse } from "next/server";
import { appsecElasticConfig, fetchAppSecSummary } from "@/lib/elastic-appsec";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET() {
  if (!appsecElasticConfig()) {
    return NextResponse.json({ configured: false, summary: null });
  }
  try {
    const summary = await fetchAppSecSummary();
    return NextResponse.json({ configured: true, summary });
  } catch (err) {
    const message = err instanceof DashboardError ? err.message : "Could not reach the AppSec Elastic index.";
    return NextResponse.json({ configured: true, summary: null, error: message }, { status: 502 });
  }
}
