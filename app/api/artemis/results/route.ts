import { NextResponse } from "next/server";
import { artemisConfig, artemisTaskResults } from "@/lib/artemis";

export const dynamic = "force-dynamic";

// Diagnostic: return the first few raw Artemis task-result objects so the
// finding field-mapping can be verified against this instance's schema.
// Session-gated by the edge proxy (not in the health allow-list).
export async function GET() {
  if (!artemisConfig()) {
    return NextResponse.json(
      { error: "Artemis is not configured. Set ARTEMIS_API_URL and ARTEMIS_API_TOKEN." },
      { status: 400 },
    );
  }
  try {
    const rows = await artemisTaskResults(3, 1);
    return NextResponse.json({ count: rows.length, sample: rows });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to reach Artemis." },
      { status: 502 },
    );
  }
}
