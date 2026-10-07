import { NextResponse } from "next/server";
import { createCompany, ensureHydrated, listCompanies } from "@/lib/store";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";
import { getRiskSummaryByCompany, riskScoringDatabase } from "@/lib/risk-scoring-store";
import { stringFieldError } from "@/lib/validate";

export const dynamic = "force-dynamic";

export async function GET() {
  await ensureHydrated();
  const companies = listCompanies();
  // Merge in the real RBVM risk figures (finding_risk) alongside the legacy
  // composite score -- best-effort: a company list must never break because
  // the risk-scoring database is unreachable or a tenant has no Spotlight
  // data yet (undefined, not 0, for "never scored").
  if (elasticVulnEnabled()) {
    try {
      const db = await riskScoringDatabase();
      const summaries = await getRiskSummaryByCompany(db);
      for (const company of companies) {
        const summary = summaries.get(company.id);
        if (summary) { company.swath1Open = summary.swath1Open; company.totalOpenRisk = summary.totalOpenRisk; }
      }
    } catch (err) {
      console.error("[companies] could not load RBVM risk summary:", err instanceof Error ? err.message : err);
    }
  }
  return NextResponse.json({ companies });
}

export async function POST(request: Request) {
  await ensureHydrated();
  let body: {
    name?: string;
    industry?: string;
    contactName?: string;
    contactEmail?: string;
  };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const fieldError = stringFieldError(body, ["name", "industry", "contactName", "contactEmail"]);
  if (fieldError) return NextResponse.json({ error: fieldError }, { status: 400 });
  const result = createCompany({
    name: body.name ?? "",
    industry: body.industry,
    contactName: body.contactName,
    contactEmail: body.contactEmail,
    // A human typed this exact name and submitted the form -- unlike a
    // sync's auto-create, that's real signal of intent, so a near-duplicate
    // warning doesn't apply here (see createCompany in lib/store.ts).
    allowNearDuplicate: true,
  });
  if ("error" in result) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
  return NextResponse.json({ company: result }, { status: 201 });
}
