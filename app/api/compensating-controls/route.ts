import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { createCompensatingControl, ensureHydrated, listCompensatingControls } from "@/lib/store";
import type { CompensatingControlStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ controls: listCompensatingControls(companyId) });
}

export async function POST(request: Request) {
  await ensureHydrated();
  let body: {
    companyId?: string;
    title?: string;
    description?: string;
    cveMatch?: string | null;
    assetMatch?: string | null;
    effectivenessPct?: number;
    status?: CompensatingControlStatus;
    evidence?: string;
    reviewBy?: string | null;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  if (!body.companyId) {
    return NextResponse.json({ error: "companyId is required." }, { status: 400 });
  }
  const session = await getServerSession(authOptions);
  const createdBy = session?.user?.email ?? session?.user?.name ?? "unknown";

  const result = await createCompensatingControl({
    companyId: body.companyId,
    title: body.title ?? "",
    description: body.description,
    cveMatch: body.cveMatch,
    assetMatch: body.assetMatch,
    effectivenessPct: Number(body.effectivenessPct),
    status: body.status,
    evidence: body.evidence,
    reviewBy: body.reviewBy,
    createdBy,
  });
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ control: result }, { status: 201 });
}
