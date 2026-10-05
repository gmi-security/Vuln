import { NextResponse } from "next/server";
import { appsecElasticConfig, fetchAppSecRepoDetail } from "@/lib/elastic-appsec";
import { DashboardError } from "@/lib/elastic-dashboard";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ repo: string }> },
) {
  if (!appsecElasticConfig()) {
    return NextResponse.json({ configured: false, detail: null });
  }
  const { repo } = await params;
  const repository = decodeURIComponent(repo);
  try {
    const detail = await fetchAppSecRepoDetail(repository);
    return NextResponse.json({ configured: true, detail });
  } catch (err) {
    const message = err instanceof DashboardError ? err.message : "Could not reach the AppSec Elastic index.";
    return NextResponse.json({ configured: true, detail: null, error: message }, { status: 502 });
  }
}
