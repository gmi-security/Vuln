import { NextResponse } from "next/server";
import { ensureHydrated, pivotOsintToNessus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Queue targeted Nessus scans of the assets OSINT flagged as exposed.
export async function POST() {
  try {
    await ensureHydrated();
    const result = await pivotOsintToNessus();
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Attack-surface pivot failed." },
      { status: 502 },
    );
  }
}
