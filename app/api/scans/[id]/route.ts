import { NextResponse } from "next/server";
import { ensureHydrated, getScan, listFindings, scanAction } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }
  return NextResponse.json({ scan, findings: listFindings({ scanId: id }) });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  let body: { action?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const action = body.action as "pause" | "resume" | "stop" | "delete" | "rescan";
  if (!["pause", "resume", "stop", "delete", "rescan"].includes(action)) {
    return NextResponse.json({ error: "Unknown action." }, { status: 400 });
  }
  const result = await scanAction(id, action);
  if ("error" in result) {
    const status = result.error === "Scan not found." ? 404 : 400;
    return NextResponse.json({ error: result.error }, { status });
  }
  return NextResponse.json(result);
}
