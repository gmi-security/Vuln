import { NextResponse } from "next/server";
import { ensureHydrated, listCompanies, listScans, startScan } from "@/lib/store";
import { adminTokenOk } from "@/lib/admin-auth";

export const dynamic = "force-dynamic";

// Token-protected admin action: for every company with at least one Nessus
// scan on record, launches a Vulners Bridge (gmi-vuln-api) scan against the
// union of that company's Nessus-scanned hosts. Purely additive — reads
// existing Nessus scan data, deletes/overwrites nothing. Pass ?dryRun=1 to
// preview the company/target list without launching anything.
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
    const nessusTargets = Array.from(
      new Set(
        (await listScans({ companyId: company.id }))
          .filter((scan) => scan.connector === "nessus")
          .flatMap((scan) => scan.targets),
      ),
    );
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
