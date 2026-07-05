import { NextResponse } from "next/server";
import { ensureHydrated, syncAllConnectors } from "@/lib/store";

export const dynamic = "force-dynamic";

// Session-gated: pull results from every configured connector in one shot.
export async function POST() {
  await ensureHydrated();
  const results = await syncAllConnectors();
  return NextResponse.json({ results });
}
