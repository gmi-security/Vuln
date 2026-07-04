import { NextResponse } from "next/server";
import { ensureHydrated, importFromIntune } from "@/lib/store";

export const dynamic = "force-dynamic";

// Sync Intune managed devices into the internal org's asset inventory.
export async function POST() {
  await ensureHydrated();
  const result = await importFromIntune();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
