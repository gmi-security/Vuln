import { NextResponse } from "next/server";
import { burpStatus } from "@/lib/burp";

export const dynamic = "force-dynamic";

// Reachability probe — returns only configuration + liveness, no issue data,
// so it is safe to expose for diagnostics.
export async function GET() {
  return NextResponse.json(await burpStatus());
}
