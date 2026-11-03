import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { readVerifiedGreenboneCapacity } from "@/lib/greenbone-capacity";

export const dynamic = "force-dynamic";

// Diagnostic only. No scan creation, reservation, scheduling, hydration,
// database schema creation or configuration changes.
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    const capacity = await readVerifiedGreenboneCapacity();
    return NextResponse.json({ scannerCapacityVerified: true, capacity }, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    // No error details or credentials exposed to the caller.
    return NextResponse.json({
      scannerCapacityVerified: false,
      reason: "Complete, fresh Greenbone scanner capacity could not be established. Dispatch must remain disabled.",
    }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
