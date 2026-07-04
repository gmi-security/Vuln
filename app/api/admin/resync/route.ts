import { NextResponse } from "next/server";
import { resyncFromNessus } from "@/lib/store";

export const dynamic = "force-dynamic";

// Token-protected admin action: wipe all data and repopulate from the real
// Nessus scanner (clears demo/stub data). Requires ?token= or an
// x-admin-token header matching ADMIN_TOKEN.
export async function POST(request: Request) {
  const token =
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    "";
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  const clearInventory =
    new URL(request.url).searchParams.get("clearInventory") === "1";
  const result = await resyncFromNessus({ clearInventory });
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
