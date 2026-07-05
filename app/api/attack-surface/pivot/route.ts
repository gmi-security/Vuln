import { NextResponse } from "next/server";
import { ensureHydrated, pivotOsintToNessus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Queue targeted Nessus scans of the assets OSINT flagged as exposed.
export async function POST() {
  await ensureHydrated();
  const result = await pivotOsintToNessus();
  return NextResponse.json({ result });
}
