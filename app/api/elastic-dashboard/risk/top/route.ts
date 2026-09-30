import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { listTopRisk, riskScoringDatabase } from "@/lib/risk-scoring-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    const db = await riskScoringDatabase();
    const result = await listTopRisk(db, {
      companyId: params.get("companyId") ?? undefined,
      tenantKey: params.get("tenantKey") ?? undefined,
      swath: params.get("swath") ? Number(params.get("swath")) : undefined,
      kevOnly: params.get("kev") === "1",
      internetExposedOnly: params.get("internetExposed") === "1",
      minScore: params.get("minScore") ? Number(params.get("minScore")) : undefined,
      limit: params.get("limit") ? Number(params.get("limit")) : undefined,
      offset: params.get("offset") ? Number(params.get("offset")) : undefined,
    });
    return dashboardJson(result);
  } catch (error) { return dashboardFailure(error); }
}
