import { NextResponse } from "next/server";
import { ensureHydrated, importFromBurp } from "@/lib/store";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

// Live pull from Burp Suite Enterprise (GraphQL). Session-gated via the edge
// proxy. Returns 400 with guidance when BURP_API_URL/BURP_API_KEY are unset —
// use the XML upload route in that case.
export async function POST() {
  await ensureHydrated();
  const result = await importFromBurp();
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
