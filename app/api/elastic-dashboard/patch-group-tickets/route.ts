import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { listGroupTickets } from "@/lib/patch-group-ticket-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess();
    const params = new URL(request.url).searchParams;
    return dashboardJson(await listGroupTickets(params.get("review") === "1", Number(params.get("page") ?? 1)));
  } catch (error) { return dashboardFailure(error); }
}
