import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { getRiskSummary, riskScoringDatabase } from "@/lib/risk-scoring-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    const db = await riskScoringDatabase();
    return dashboardJson(await getRiskSummary(db, params.get("companyId") ?? undefined));
  } catch (error) { return dashboardFailure(error); }
}
