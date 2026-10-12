import { NextResponse } from "next/server";
import { appsecElasticConfig, fetchAppSecRepoDetail } from "@/lib/elastic-appsec";
import { DashboardError } from "@/lib/elastic-dashboard";
import { appsecCompanyParameter, loadCustomerAppSecScope } from "@/lib/customer-appsec-routing-server";

export const dynamic = "force-dynamic";
const headers = { "Cache-Control": "private, no-store" };
export async function GET(request: Request, { params }: { params: Promise<{ repo: string }> }) {
  let companyId: string | null = null;
  try {
    companyId = appsecCompanyParameter(request);
    const reviewed = await loadCustomerAppSecScope(companyId);
    if (!reviewed && !appsecElasticConfig()) return NextResponse.json({ companyId, configured: false, detail: null }, { headers });
    const { repo } = await params;
    let repository: string;
    try { repository = decodeURIComponent(repo); } catch { throw new DashboardError("Invalid repository path.", 400); }
    const detail = await fetchAppSecRepoDetail(repository, reviewed?.scope);
    await reviewed?.recheck();
    return NextResponse.json({ companyId, configured: true, detail }, { headers });
  } catch (err) {
    const safe = err instanceof DashboardError && [400, 404, 409].includes(err.status);
    return NextResponse.json({ companyId, configured: true, detail: null,
      error: safe ? err.message : "Could not load this AppSec repository. Check source access and approval." }, { status: safe ? err.status : 502, headers });
  }
}
