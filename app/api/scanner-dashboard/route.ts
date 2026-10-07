import { NextResponse } from "next/server";
import { scannerElasticConfig } from "@/lib/elastic-scanner-export";
import { fetchScannerSummary, fetchScannerCompanyRows } from "@/lib/elastic-scanner-dashboard";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET() {
  if (!scannerElasticConfig()) {
    return NextResponse.json({ configured: false, summary: null, companies: null });
  }
  try {
    const summary = await fetchScannerSummary();
    // The per-company table is a secondary view on the same page -- a
    // failure fetching it must not take down the summary tiles above it.
    const companies = await fetchScannerCompanyRows().catch(() => null);
    return NextResponse.json({ configured: true, summary, companies });
  } catch (err) {
    const message = err instanceof DashboardError ? err.message : "Could not reach the scanner Elastic indices.";
    return NextResponse.json({ configured: true, summary: null, companies: null, error: message }, { status: 502 });
  }
}
