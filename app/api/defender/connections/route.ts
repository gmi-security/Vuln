import { defenderAccess, defenderBody, defenderCompany, defenderFailure, defenderJson } from "@/lib/defender-http";
import { createDefenderClient, DefenderError } from "@/lib/defender-client";
import { defenderStore } from "@/lib/defender-store";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await defenderAccess(request);
    const filter = new URL(request.url).searchParams.get("companyId");
    const companyId = filter ? await defenderCompany(filter) : undefined;
    return defenderJson({ connections:await defenderStore().list(companyId) });
  } catch (error) { return defenderFailure(error); }
}
export async function POST(request: Request) {
  try {
    const actor = await defenderAccess(request,true);
    const body = await defenderBody(request,8192) as Record<string,unknown>;
    if (!body || typeof body !== "object") throw new DefenderError("Invalid connection.");
    const companyId = await defenderCompany(body.companyId);
    for (const key of ["tenantId","clientId","clientSecret"]) {
      if (body[key] !== undefined && typeof body[key] !== "string") throw new DefenderError("Invalid credential field.");
    }
    const credentials = await defenderStore().credentials(companyId,{
      tenantId:body.tenantId as string, clientId:body.clientId as string, clientSecret:body.clientSecret as string,
    });
    if (body.action === "test") return defenderJson(await createDefenderClient(credentials).test());
    if (body.action !== "save" || typeof body.daily !== "boolean") throw new DefenderError("Choose save or test.");
    await defenderStore().save({ ...credentials,companyId,daily:body.daily },actor);
    return defenderJson({ saved:true });
  } catch (error) { return defenderFailure(error); }
}
