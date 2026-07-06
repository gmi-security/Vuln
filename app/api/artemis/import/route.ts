import { NextResponse } from "next/server";
import { ensureHydrated, importFromArtemis } from "@/lib/store";

export const dynamic = "force-dynamic";

// Pull Artemis "interesting" task results in as findings, grouped by tag ->
// company.
export async function POST() {
  try {
    await ensureHydrated();
    const result = await importFromArtemis();
    if ("error" in result) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }
    return NextResponse.json({ result });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Artemis import failed." },
      { status: 502 },
    );
  }
}
