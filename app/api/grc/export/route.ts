import { NextResponse } from "next/server";
import { ensureHydrated, exportToGrc } from "@/lib/store";

export const dynamic = "force-dynamic";

// Push vulnerability risk into the GRC (OpenGRC) for audit/compliance.
export async function POST(request: Request) {
  await ensureHydrated();
  let body: { companyId?: string } = {};
  try {
    body = await request.json();
  } catch {
    // no body = export all companies
  }
  const result = await exportToGrc(
    body.companyId ? { companyId: body.companyId } : undefined,
  );
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ result });
}
