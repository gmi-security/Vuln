import { withDurablePlatformMutation } from "@/lib/platform-mutation-route";
import { NextResponse } from "next/server";
import { ensureHydrated, importFromNessus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Pull the scanner's folders in as companies (and their scans + findings).
async function POSTHandler() {
  try {
    await ensureHydrated();
    const result = await importFromNessus();
    if ("error" in result) {
      return NextResponse.json({ error: result.error }, { status: 400 });
    }
    return NextResponse.json({ result });
  } catch (err) {
    console.error("[nessus/import]", err);
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Nessus import failed." },
      { status: 502 },
    );
  }
}

export const POST = withDurablePlatformMutation(POSTHandler);
