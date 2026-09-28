import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { autoCreateHighSeverityTickets } from "@/lib/group-auto-create";
import { backfillWorstSeverity } from "@/lib/group-severity-backfill";
import { backfillAppCompanyId } from "@/lib/group-company-backfill";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    await dashboardAccess(request, true);
    // Self-healing: catch up any draft still missing worst_severity or
    // appCompanyId (from before those existed/were configured) before
    // checking eligibility, so a manual run never misses a draft that's
    // only stale on paper.
    await Promise.all([backfillWorstSeverity(), backfillAppCompanyId()]);
    return dashboardJson(await autoCreateHighSeverityTickets());
  } catch (error) { return dashboardFailure(error); }
}
