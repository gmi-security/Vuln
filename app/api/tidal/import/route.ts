import { NextResponse } from "next/server";
import { ensureHydrated, importFromTidal } from "@/lib/store";

export const dynamic = "force-dynamic";

// Sync the Tidal.io asset inventory into companies + assets and reprice risk.
export async function POST() {
  await ensureHydrated();
  const result = await importFromTidal();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
