import { NextResponse } from "next/server";
import { appsecElasticConfig, fetchAppSecSummary, fetchAppSecTrend } from "@/lib/elastic-appsec";
import { DashboardError } from "@/lib/elastic-dashboard";
import { appsecCompanyParameter, appsecCustomerSetup, loadCustomerAppSecScope } from "@/lib/customer-appsec-routing-server";

export const dynamic = "force-dynamic";
const headers = { "Cache-Control": "private, no-store" };
// Session and organization membership remain enforced by proxy.ts.
export async function GET(request: Request) {
  let companyId: string | null = null;
  try {
    companyId = appsecCompanyParameter(request);
    if (new URL(request.url).searchParams.get("setup") === "1")
      return NextResponse.json(await appsecCustomerSetup(), { headers });
    const reviewed = await loadCustomerAppSecScope(companyId);
    if (!reviewed && !appsecElasticConfig()) return NextResponse.json({ companyId, configured: false, summary: null, trend: null }, { headers });
    const summary = await fetchAppSecSummary(reviewed?.scope);
    let trendError: string | null = null;
    const trend = await fetchAppSecTrend(reviewed?.scope).catch(() => { trendError = "AppSec trend is unavailable. Summary results are still shown."; return null; });
    await reviewed?.recheck();
    return NextResponse.json({ companyId, configured: true, summary, trend, trendError }, { headers });
  } catch (err) {
    // Upstream ES error bodies can include repository identities. Reviewed reads
    // expose only routing messages or a generic source failure.
    const safe = err instanceof DashboardError && [400, 404, 409].includes(err.status);
    const message = safe ? err.message : "Could not load AppSec data. Check source access and repository approval.";
    return NextResponse.json({ companyId, configured: true, summary: null, trend: null, error: message }, { status: safe ? err.status : 502, headers });
  }
}
