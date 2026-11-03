import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { ensureHydrated, nessusOffsetScheduleMatrix } from "@/lib/store";
import { loadReviewedScannerRoutes } from "@/lib/customer-scanner-routing-server";
import { buildExternalScanPlan } from "@/lib/external-scan-plan";

export const dynamic = "force-dynamic";

// Strictly read-only. Imported findings are not authorization.
// Deliberately no POST/dispatch path and no alteration of scan admission.
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    await ensureHydrated();
    const routes = await loadReviewedScannerRoutes("vulners");
    const matrix = await nessusOffsetScheduleMatrix();
    return NextResponse.json(buildExternalScanPlan(matrix, routes), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({ error: "Approved external scan plan is unavailable. No scans launched." },
      { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
