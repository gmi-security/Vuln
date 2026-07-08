import { NextResponse } from "next/server";
import { nmapStatus } from "@/lib/nmap";

export const dynamic = "force-dynamic";

// Reachability probe — returns only configuration + liveness, no scan data,
// so it is safe to expose for diagnostics.
export async function GET() {
  return NextResponse.json(await nmapStatus());
}
