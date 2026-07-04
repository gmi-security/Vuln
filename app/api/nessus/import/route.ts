import { NextResponse } from "next/server";
import { importFromNessus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Pull the scanner's folders in as companies (and their scans + findings).
export async function POST() {
  const result = await importFromNessus();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
