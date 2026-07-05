import { NextResponse } from "next/server";
import { ensureHydrated, previewOsintTargets } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated: which customers/domains a quarterly OSINT sweep would hit.
export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ preview: previewOsintTargets() });
}
