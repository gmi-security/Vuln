import { NextResponse } from "next/server";
import { ensureHydrated, mergeCompanies } from "@/lib/store";

export const dynamic = "force-dynamic";

// Merge this company (the duplicate/source) into another one, reassigning
// its assets/findings/scans and deleting it once empty. Use when a sync's
// name-matching missed an existing company and created a near-duplicate
// (e.g. "GCON" vs "GCON Inc.") instead of attaching to it.
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  let body: { intoId?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  if (!body.intoId) {
    return NextResponse.json({ error: "intoId is required." }, { status: 400 });
  }
  const result = mergeCompanies(id, body.intoId);
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
