import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { DashboardError } from "@/lib/elastic-dashboard";
import { clearSwathOverride, overrideSwath, riskScoringDatabase } from "@/lib/risk-scoring-store";
export const dynamic = "force-dynamic";

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const access = await dashboardAccess(request, true);
    const { id } = await params;
    const body = await request.json().catch(() => ({})) as { swath?: number; reason?: string; clear?: boolean };
    const db = await riskScoringDatabase();
    if (body.clear) {
      await clearSwathOverride(db, id, access.actor ?? "analyst");
      return dashboardJson({ ok: true });
    }
    if (!body.swath || ![1, 2, 3, 4].includes(body.swath)) throw new DashboardError("Choose a Swath between 1 and 4.");
    if (!body.reason?.trim()) throw new DashboardError("An override reason is required so this stays explainable later.");
    await overrideSwath(db, id, body.swath, access.actor ?? "analyst", body.reason.trim());
    return dashboardJson({ ok: true });
  } catch (error) { return dashboardFailure(error); }
}
