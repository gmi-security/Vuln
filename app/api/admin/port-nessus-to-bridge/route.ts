import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// RETIRED: the former POST path gathered every Nessus-scanned alias and
// historical finding asset for a customer, then created Greenbone tasks
// against that cross-scan union. Those are NOT the configured or confirmed
// host targets of an individual Nessus scan occurrence.
//
// This endpoint deliberately cannot launch a scan, including when a caller
// omits dryRun=1. Re-enable work only through the separate reviewed
// per-occurrence dispatcher with approved scope, actual Nessus target/host
// evidence and a durable globally bounded scan claim.
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  return NextResponse.json({
    error: "Legacy company-wide Nessus-to-Greenbone port is retired. It cannot guarantee identical scan targets.",
    action: "Use read-only per-scan parity review, then the independently approved controlled dispatcher.",
    scansLaunched: 0,
  }, { status: 409, headers: { "Cache-Control": "no-store" } });
}
