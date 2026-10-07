import { defenderAccess, defenderCompany, defenderFailure, defenderJson } from "@/lib/defender-http";
import { defenderStore } from "@/lib/defender-store";
import { DefenderError } from "@/lib/defender-client";
import { defenderProjectedRun } from "@/lib/store";
import { defenderPublicationPending } from "@/lib/defender-platform";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    await defenderAccess(request);
    const params = new URL(request.url).searchParams;
    const companyId = await defenderCompany(params.get("companyId"));
    const view = params.get("view") || "cves";
    if (!["cves","devices","findings"].includes(view)) throw new DefenderError("Unknown Defender view.");
    const offset = Math.max(0,Math.min(10_000_000,parseInt(params.get("offset") || "0",10) || 0));
    const cve = (params.get("cve") || "").toUpperCase();
    if (cve && !/^CVE-\d{4}-\d{4,}$/.test(cve)) throw new DefenderError("Invalid CVE filter.");
    const result = await defenderStore().results(companyId,view,offset,cve);
    return defenderJson({ ...result, platformPublished:!!result.runId && defenderProjectedRun(companyId) === result.runId && !defenderPublicationPending(companyId) });
  } catch (error) { return defenderFailure(error); }
}
