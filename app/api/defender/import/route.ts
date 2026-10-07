import { defenderAccess, defenderBody, defenderCompany, defenderFailure, defenderJson } from "@/lib/defender-http";
import { defenderStore } from "@/lib/defender-store";
import { triggerDefenderWorker } from "@/lib/defender-worker";
import { syncDefenderEnvironment } from "@/lib/defender-config";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  try {
    const actor = await defenderAccess(request,true);
    const body = await defenderBody(request,1024) as { companyId?: unknown };
    const companyId = await defenderCompany(body?.companyId);
    await syncDefenderEnvironment();
    const runId = await defenderStore().enqueue(companyId,actor);
    void triggerDefenderWorker();
    return defenderJson({ runId,queued:true },202);
  } catch (error) { return defenderFailure(error); }
}
