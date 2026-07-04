import { NextResponse } from "next/server";
import { listFindings } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("scanId") ?? undefined;
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ findings: listFindings({ scanId, companyId }) });
}
