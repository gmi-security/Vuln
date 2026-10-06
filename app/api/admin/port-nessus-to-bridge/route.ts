import { NextResponse } from "next/server";
import { ensureHydrated, listCompanies, nessusBridgeTargetsForCompany, startScan } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// Token-protected admin action: for every company with at least one Nessus
// finding on record, launches a Vulners Bridge (gmi-vuln-api) scan against
// the union of that company's Nessus-scanned hosts. Purely additive — reads
// existing Nessus data, deletes/overwrites nothing. Pass ?dryRun=1 to
// preview the company/target list without launching anything.
//
// Targets come from Finding.asset, not Scan.targets: an imported Nessus
// scan (vendor.imported: true) only records a hostsScanned *count*, not the
// host list — the actual hostnames only exist on that scan's findings.
export async function POST(request: Request) {
  if (!adminTokenOk(request)) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  await ensureHydrated();
  const dryRun = new URL(request.url).searchParams.get("dryRun") === "1";

  const results: Array<{
    companyId: string;
    companyName: string;
    targets: string[];
    scanId?: string;
    error?: string;
  }> = [];

  for (const company of listCompanies()) {
    const nessusTargets = nessusBridgeTargetsForCompany(company.id);
    if (!nessusTargets.length) continue;

    if (dryRun) {
      results.push({ companyId: company.id, companyName: company.name, targets: nessusTargets });
      continue;
    }

    const result = await startScan({
      name: `GMI scan: ${company.name} (ported from Nessus)`,
      connector: "vulners",
      profile: "full-fast",
      targets: nessusTargets,
      companyId: company.id,
      requestedBy: "system@gmi.com",
    });

    results.push(
      "error" in result
        ? { companyId: company.id, companyName: company.name, targets: nessusTargets, error: result.error }
        : { companyId: company.id, companyName: company.name, targets: nessusTargets, scanId: result.id },
    );
  }

  return NextResponse.json({ dryRun, portedCompanies: results.length, results });
}
