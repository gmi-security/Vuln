import { NextResponse } from "next/server";
import { ensureHydrated, syncAllConnectors } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated: pull results from every configured connector in one shot.
export async function POST() {
  try {
    await ensureHydrated();
    const results = await syncAllConnectors();
    return NextResponse.json({ results });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Sync-all failed." },
      { status: 502 },
    );
  }
}
