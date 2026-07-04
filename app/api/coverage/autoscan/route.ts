import { NextResponse } from "next/server";
import { autoScanGaps } from "@/lib/store";

export const dynamic = "force-dynamic";

// Launch scans for all known-but-unscanned assets (the coverage gap).
export async function POST() {
  const result = await autoScanGaps();
  return NextResponse.json({ result });
}
