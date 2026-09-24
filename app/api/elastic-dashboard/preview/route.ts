import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { previewQuery } from "@/lib/elastic-dashboard-store";
import { validateQuery } from "@/lib/elastic-dashboard";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    const { actor } = await dashboardAccess(request, true);
    const body = await dashboardBody(request) as { query?: unknown } | null;
    return dashboardJson({ result: await previewQuery(validateQuery(body?.query), actor) });
  } catch (error) { return dashboardFailure(error); }
}
