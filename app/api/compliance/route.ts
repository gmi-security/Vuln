import { NextResponse } from "next/server";
import { computeCompliance, ensureHydrated } from "@/lib/store";

export const dynamic = "force-dynamic";

// PCI DSS 4.0 vulnerability-management compliance posture per company.
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  return NextResponse.json({ compliance: computeCompliance({ companyId }) });
}
