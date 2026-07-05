import { NextResponse } from "next/server";
import { computeCompliance, ensureHydrated } from "@/lib/store";
import { listFrameworks } from "@/lib/compliance";

export const dynamic = "force-dynamic";

// Multi-framework vulnerability-management compliance posture per company.
// ?framework=pci|nist-800-53|nist-800-171|cmmc|hipaa|fedramp (default pci)
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  const framework = searchParams.get("framework") ?? undefined;
  return NextResponse.json({
    compliance: computeCompliance({ companyId, framework }),
    frameworks: listFrameworks(),
  });
}
