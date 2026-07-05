import { NextResponse } from "next/server";
import { computeRemediationSla, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  return NextResponse.json({ sla: computeRemediationSla() });
}
