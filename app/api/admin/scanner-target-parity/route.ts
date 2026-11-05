import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { loadReviewedScannerRoutes } from "@/lib/customer-scanner-routing-server";
import { compareApprovedScannerTargets } from "@/lib/approved-scanner-target-parity";

export const dynamic = "force-dynamic";

// Admin-only read: approval metadata may contain private IPs/customer targets.
// This cannot create, start, schedule, import, or clear any scan.
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    const [nessus, vulners] = await Promise.all([
      loadReviewedScannerRoutes("nessus"),
      loadReviewedScannerRoutes("vulners"),
    ]);
    return NextResponse.json(compareApprovedScannerTargets(nessus, vulners), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json({
      error: "Reviewed source scopes could not be verified; scanning parity is unknown.",
    }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
