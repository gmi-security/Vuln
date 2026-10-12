import { dashboardAccess, dashboardBody, dashboardFailure, dashboardJson } from "@/lib/elastic-dashboard-http";
import { createGroupTicket, groupTicketAction, readGroupTicket, reviewGroupTicket, setGroupTicketPriority } from "@/lib/patch-group-ticket-store";
import { assertCustomerGroup } from "@/lib/customer-cve-service";
export const dynamic = "force-dynamic";
type Context = { params: Promise<{ id: string }> };
export async function GET(request: Request, context: Context) {
  try { await dashboardAccess(); const {id}=await context.params;const params=new URL(request.url).searchParams;
    if(params.has("companyId"))await assertCustomerGroup(params.get("companyId") ?? "",id);
    return dashboardJson(await readGroupTicket(id, params.get("packet") === "1")); } catch (error) { return dashboardFailure(error); }
}
export async function POST(request: Request, context: Context) {
  try {
    const { actor } = await dashboardAccess(request, true), { id } = await context.params;
    const params=new URL(request.url).searchParams;
    if(params.has("companyId"))await assertCustomerGroup(params.get("companyId") ?? "",id);
    const body = await dashboardBody(request, 256 * 1024) as Record<string, unknown>;
    if (body?.action === "approve" || body?.action === "dismiss" || body?.action === "reopen")
      return dashboardJson(await reviewGroupTicket(id, body.action, actor));
    if (body?.action === "set-priority") return dashboardJson(await setGroupTicketPriority(id, body.priorityId, actor));
    return dashboardJson(body?.action === "create" ? await createGroupTicket(id, body, actor) : await groupTicketAction(id, body?.action, actor), 202);
  } catch (error) { return dashboardFailure(error); }
}
