import { NextResponse } from "next/server";
import { ensureHydrated, importFromDefender } from "@/lib/store";

export const dynamic = "force-dynamic";

// Import Microsoft Defender device vulnerabilities as findings.
export async function POST() {
  await ensureHydrated();
  const result = await importFromDefender();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
