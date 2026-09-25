import { dashboardAccess, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { readCWOptions } from "@/lib/patch-ticket-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await dashboardAccess(); const q = new URL(request.url).searchParams;
    return dashboardJson(await readCWOptions(q.get("kind") ?? "", q.has("boardId") ? Number(q.get("boardId")) : undefined, Number(q.get("page") ?? 1), q.get("search") ?? "", q.has("selectedId") ? Number(q.get("selectedId")) : undefined));
  } catch (error) { return dashboardFailure(error); }
}
