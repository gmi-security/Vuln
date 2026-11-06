import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { ensureHydrated, nessusOffsetScheduleMatrix } from "@/lib/store";
import { loadReviewedScannerRoutes } from "@/lib/customer-scanner-routing-server";
import { buildExternalScanPlan, type ExternalNessusDefinition } from "@/lib/external-scan-plan";
import {
  nessusConfig, nessusListScans, nessusConfiguredTargetsForDefinition,
} from "@/lib/nessus";

export const dynamic = "force-dynamic";

// Admin-only, strictly read-only. Unlike the retired company-wide planner,
// target candidates come from the specific Nessus scan editor definition.
// This plan is NOT proof that Nessus assessed the target in a completed
// historical run, and never creates/starts or schedules Greenbone tasks.
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    await ensureHydrated();
    const [vulners, nessus] = await Promise.all([
      loadReviewedScannerRoutes("vulners"),
      loadReviewedScannerRoutes("nessus"),
    ]);
    const matrix = await nessusOffsetScheduleMatrix();
    // No reviewed routes means NO Nessus calls are necessary, and cannot
    // accidentally construct candidate scans from historical findings.
    if (vulners === null || nessus === null) {
      return NextResponse.json(buildExternalScanPlan(matrix, vulners, nessus), {
        headers: { "Cache-Control": "no-store" },
      });
    }
    const cfg = nessusConfig();
    if (!cfg) throw new Error("Nessus connection unavailable.");
    // Require live roster folder membership. No matching by customer name
    // or by imported historical company ID is authoritative.
    const roster = await nessusListScans(cfg);
    if (roster.length > 1000) throw new Error("Oversized Nessus scan roster.");
    const scanById = new Map(roster.map(scan => [scan.id, scan]));
    const scheduled = matrix.companies.flatMap(c =>
      c.scans.filter(s => s.enabled).map(s=>({
        companyId:c.companyId, nessusScanId:s.nessusScanId,
      }))
    );
    if (scheduled.length > 100) throw new Error("Oversized enabled scan matrix.");
    const definitions:ExternalNessusDefinition[]=[];
    // Bound authenticated Nessus GET concurrency. Individual parser/roster
    // failure leaves definition absent, so that scan fails closed in plan.
    for(let i=0;i<scheduled.length;i+=4) {
      const batch=await Promise.all(scheduled.slice(i,i+4).map(async scan=>{
        const matches=nessus.filter(r=>r.provider==="nessus"&&
          r.companyId===scan.companyId);
        if(matches.length!==1) return null;
        const folderId=Number(matches[0].sourceScope);
        if(!Number.isSafeInteger(folderId)||folderId<1||
           scanById.get(scan.nessusScanId)?.folderId!==folderId)
          return null;
        try {
          const read=await nessusConfiguredTargetsForDefinition(scan.nessusScanId,cfg);
          return {
            companyId:scan.companyId,
            nessusScanId:scan.nessusScanId,
            folderId,targets:read.targets,
            source:"nessus-editor" as const,
          };
        }catch{return null;}
      }));
      for(const item of batch)if(item)definitions.push(item);
    }
    return NextResponse.json(buildExternalScanPlan(matrix,vulners,nessus,definitions),{
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({
      error: "Independently reviewed scanner scope or per-Nessus-scan target definition unavailable. No scans launched.",
    },{status:503,headers:{"Cache-Control":"no-store"}});
  }
}
