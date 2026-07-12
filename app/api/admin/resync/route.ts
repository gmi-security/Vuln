import { NextResponse } from "next/server";
import { resyncFromNessus } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// Token-protected admin action: wipe all data and repopulate from the real
// Nessus scanner (clears demo/stub data). Requires an Authorization: Bearer
// or x-admin-token header matching ADMIN_TOKEN (no query-param form — that
// would leak the token into access logs).
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
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
