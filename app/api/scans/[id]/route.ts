import { NextResponse } from "next/server";
import { getScan, listFindings, scanAction } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const scan = getScan(id);
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }
  return NextResponse.json({ scan, findings: listFindings({ scanId: id }) });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
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
  const result = scanAction(id, action);
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json(result);
}
