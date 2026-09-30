import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { getJobRun } from "@/lib/background-job-runs";
import { DashboardError } from "@/lib/elastic-dashboard";
export const dynamic = "force-dynamic";

const KNOWN_JOBS = new Set(["validate-closures", "abandon-and-replace", "close-and-recut", "risk-refresh"]);

export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const job = new URL(request.url).searchParams.get("job") ?? "";
    if (!KNOWN_JOBS.has(job)) throw new DashboardError("Unknown background job.", 404);
    return dashboardJson({ run: await getJobRun(job) });
  } catch (error) { return dashboardFailure(error); }
}
