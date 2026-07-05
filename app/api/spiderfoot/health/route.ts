import { NextResponse } from "next/server";
import { spiderfootStatus } from "@/lib/spiderfoot";

export const dynamic = "force-dynamic";

// Reachability probe — returns only server liveness + scan count, no scan
// data, so it is safe to expose for diagnostics.
export async function GET() {
  return NextResponse.json(await spiderfootStatus());
}
