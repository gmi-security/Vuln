import { NextResponse } from "next/server";
import { debugAutomateSample } from "@/lib/tidal";

export const dynamic = "force-dynamic";

// TEMPORARY schema-discovery endpoint — see lib/tidal.ts's debugAutomateSample().
// Session-gated by proxy.ts like every other /api route. Remove alongside
// debugAutomateSample() once normAutomate() is written against real fields.
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const company = searchParams.get("company") ?? "Atlas";
  try {
    const result = await debugAutomateSample(company);
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}
