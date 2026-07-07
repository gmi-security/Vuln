import { NextResponse } from "next/server";
import { ensureHydrated, listFindings } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const scanId = searchParams.get("scanId") ?? undefined;
  const companyId = searchParams.get("companyId") ?? undefined;
  const kindParam = searchParams.get("kind");
  const kind =
    kindParam === "osint" || kindParam === "pentest" || kindParam === "all"
      ? kindParam
      : "vuln";
  return NextResponse.json({ findings: listFindings({ scanId, companyId, kind }) });
}
