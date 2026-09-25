import { NextResponse } from "next/server";
import { deleteCompensatingControl, ensureHydrated, updateCompensatingControl } from "@/lib/store";
import type { CompensatingControlStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  let body: {
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
  const result = await updateCompensatingControl(id, {
    ...(body.title !== undefined ? { title: body.title } : {}),
    ...(body.description !== undefined ? { description: body.description } : {}),
    ...(body.cveMatch !== undefined ? { cveMatch: body.cveMatch } : {}),
    ...(body.assetMatch !== undefined ? { assetMatch: body.assetMatch } : {}),
    ...(body.effectivenessPct !== undefined ? { effectivenessPct: Number(body.effectivenessPct) } : {}),
    ...(body.status !== undefined ? { status: body.status } : {}),
    ...(body.evidence !== undefined ? { evidence: body.evidence } : {}),
    ...(body.reviewBy !== undefined ? { reviewBy: body.reviewBy } : {}),
  });
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ control: result });
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  const result = await deleteCompensatingControl(id);
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json(result);
}
