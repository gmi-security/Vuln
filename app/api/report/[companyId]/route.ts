import { NextResponse } from "next/server";
import { computeExecReport, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ companyId: string }> },
) {
  await ensureHydrated();
  const { companyId } = await params;
  const report = computeExecReport(companyId);
  if (!report) {
    return NextResponse.json({ error: "Company not found." }, { status: 404 });
  }
  report.generatedAt = new Date().toISOString();
  return NextResponse.json({ report });
}
