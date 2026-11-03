import { NextResponse } from "next/server";
import { adminTokenOk } from "@/lib/admin-auth";
import { applicationDatabase } from "@/lib/persist";
import { inspectExternalScanReconciliation } from "@/lib/db/external-scan-reconciliation.mjs";

export const dynamic = "force-dynamic";

// Admin-only read. No hydration, schema installer, remote calls, or release.
// Reconciliation is operator-led; unknown task state keeps the slot occupied.
export async function GET(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  try {
    const pool = applicationDatabase();
    if (!pool) throw new Error("No database");
    return NextResponse.json(await inspectExternalScanReconciliation(pool), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      { error: "External scan slot unavailable or migration not installed. No scans launched." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
}
