import { NextResponse } from "next/server";
import { ensureHydrated, importFromSpiderfoot } from "@/lib/store";

export const dynamic = "force-dynamic";

// Pull finished SpiderFoot scans in as findings, grouped under the matching
// company (by scan name / target).
export async function POST() {
  try {
    await ensureHydrated();
    const result = await importFromSpiderfoot();
    if ("error" in result) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "SpiderFoot import failed." },
      { status: 502 },
    );
  }
}
