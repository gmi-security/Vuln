import { NextResponse } from "next/server";
import { ensureHydrated, previewOsintTargets } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated: which customers/domains a quarterly OSINT sweep would hit.
export async function GET() {
  await ensureHydrated();
  try { return NextResponse.json({ preview: await previewOsintTargets() }); }
  catch { return NextResponse.json({ error: "OSINT routing is unavailable or needs review." }, { status: 503 }); }
}
