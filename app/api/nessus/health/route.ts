import { NextResponse } from "next/server";
import { nessusServerStatus } from "@/lib/nessus";

export const dynamic = "force-dynamic";

// Connectivity/activation probe. Returns only scanner reachability + status
// (no credentials or scan data), so it is safe to expose for diagnostics.
export async function GET() {
  return NextResponse.json(await nessusServerStatus());
}
