import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { createGroupTicket, groupTicketAction, readGroupTicket, reviewGroupTicket } from "@/lib/patch-group-ticket-store";
export const dynamic = "force-dynamic";
type Context = { params: Promise<{ id: string }> };
export async function GET(request: Request, context: Context) {
  try { await dashboardAccess(); return dashboardJson(await readGroupTicket((await context.params).id, new URL(request.url).searchParams.get("packet") === "1")); } catch (error) { return dashboardFailure(error); }
}
export async function POST(request: Request, context: Context) {
  try {
    const { actor } = await dashboardAccess(request, true), { id } = await context.params;
    const body = await dashboardBody(request, 256 * 1024) as Record<string, unknown>;
    if (body?.action === "approve" || body?.action === "dismiss" || body?.action === "reopen")
      return dashboardJson(await reviewGroupTicket(id, body.action, actor));
    return dashboardJson(body?.action === "create" ? await createGroupTicket(id, body, actor) : await groupTicketAction(id, body?.action, actor), 202);
  } catch (error) { return dashboardFailure(error); }
}
