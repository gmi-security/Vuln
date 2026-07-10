import { NextResponse } from "next/server";
import {
  ensureHydrated,
  listFindings,
  updateFinding,
  withSlaInfo,
} from "@/lib/store";
import type { FindingStatus } from "@/lib/types";

export const dynamic = "force-dynamic";

const VALID_STATUSES: FindingStatus[] = [
  "Open",
  "In Remediation",
  "Risk Accepted",
  "False Positive",
  "Resolved",
];

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  const finding = listFindings().find((f) => f.id === id);
  if (!finding) {
    return NextResponse.json({ error: "Finding not found." }, { status: 404 });
  }
  return NextResponse.json({ finding: withSlaInfo(finding) });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await ensureHydrated();
  const { id } = await params;
  let body: { status?: FindingStatus; assignee?: string | null };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  if (body.status && !VALID_STATUSES.includes(body.status)) {
    return NextResponse.json({ error: "Unknown status." }, { status: 400 });
  }
  const result = updateFinding(id, body);
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 404 });
  }
  return NextResponse.json({ finding: withSlaInfo(result) });
}
