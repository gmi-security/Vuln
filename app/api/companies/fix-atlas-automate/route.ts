import { NextResponse } from "next/server";
import { ensureHydrated, fixAtlasAutomateCompany } from "@/lib/store";

export const dynamic = "force-dynamic";

// TEMPORARY one-shot fix — see lib/store.ts's fixAtlasAutomateCompany().
// Session-gated like the company PATCH/DELETE routes (not ADMIN_TOKEN --
// this is an ordinary data-correction action, not a destructive recovery
// tool). Remove alongside fixAtlasAutomateCompany() once run.
export async function POST() {
  await ensureHydrated();
  const result = await fixAtlasAutomateCompany();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
