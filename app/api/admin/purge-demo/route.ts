import { NextResponse } from "next/server";
import { ensureHydrated, purgeDemoData } from "@/lib/store";

export const dynamic = "force-dynamic";

// Token-protected: remove all demo/simulated scans + findings (anything not
// backed by a real scanner or an import). Requires ?token= or x-admin-token.
export async function POST(request: Request) {
  const token =
    new URL(request.url).searchParams.get("token") ??
    request.headers.get("x-admin-token") ??
    "";
  if (!process.env.ADMIN_TOKEN || token !== process.env.ADMIN_TOKEN) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const result = await purgeDemoData();
  return NextResponse.json({ result });
}
