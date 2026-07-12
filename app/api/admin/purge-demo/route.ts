import { NextResponse } from "next/server";
import { ensureHydrated, purgeDemoData } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// Token-protected: remove all demo/simulated scans + findings (anything not
// backed by a real scanner or an import). Requires an Authorization: Bearer
// or x-admin-token header matching ADMIN_TOKEN (no query-param form).
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await purgeDemoData();
  return NextResponse.json({ result });
}
