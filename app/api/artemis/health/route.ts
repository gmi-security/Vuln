import { NextResponse } from "next/server";
import { artemisStatus } from "@/lib/artemis";

export const dynamic = "force-dynamic";

// Reachability + token-validity probe (no scan data).
export async function GET() {
  return NextResponse.json(await artemisStatus());
}
