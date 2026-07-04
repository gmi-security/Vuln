import { NextResponse } from "next/server";
import { grcProbe } from "@/lib/grc";

export const dynamic = "force-dynamic";

// Temporary read-only diagnostic: reports the live GRC standards + risk schema.
export async function GET() {
  return NextResponse.json(await grcProbe());
}
