import { defenderAccess, defenderBody, defenderCompany, defenderFailure, defenderJson } from "@/lib/defender-http";
import { createDefenderClient, DefenderError } from "@/lib/defender-client";
import { defenderStore } from "@/lib/defender-store";
import { syncDefenderEnvironment } from "@/lib/defender-config";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await defenderAccess(request);
    await syncDefenderEnvironment();
    const filter = new URL(request.url).searchParams.get("companyId");
    const companyId = filter ? await defenderCompany(filter) : undefined;
    return defenderJson({ connections:await defenderStore().list(companyId) });
  } catch (error) { return defenderFailure(error); }
}
export async function POST(request: Request) {
  try {
    await defenderAccess(request,true);
    const body = await defenderBody(request,1024) as Record<string,unknown>;
    if (body?.action !== "test" || Object.keys(body).some(key=>!["action","companyId"].includes(key)))
      throw new DefenderError("Defender credentials are managed in the server environment. Only testing the configured connection is supported here.",403);
    const companyId = await defenderCompany(body.companyId);
    await syncDefenderEnvironment();
    return defenderJson(await createDefenderClient(await defenderStore().credentials(companyId)).test());
  } catch (error) { return defenderFailure(error); }
}
