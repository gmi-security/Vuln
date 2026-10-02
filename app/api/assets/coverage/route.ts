import { NextResponse } from "next/server";
import { assetCoverage, ensureHydrated, listCompanies, type AssetCoverage, type CoverageRow } from "@/lib/store";
import { elasticVulnEnabled } from "@/lib/elastic-vuln-server";
import { getScannedHostnamesByCompany, riskScoringDatabase, type HostRiskRow } from "@/lib/risk-scoring-store";

export const dynamic = "force-dynamic";

// Diff of known assets (inventory) vs scanned assets (seen in findings).
export async function GET(request: Request) {
  await ensureHydrated();
  const { searchParams } = new URL(request.url);
  const companyId = searchParams.get("companyId") ?? undefined;
  const coverage = assetCoverage({ companyId });
  // The diff above only sees scan results living in the legacy in-memory
  // store (Nessus/SpiderFoot/Artemis/Burp). CrowdStrike Spotlight findings
  // live entirely in finding_risk/Postgres and never touch that store, so a
  // tenant scanned almost exclusively via Spotlight looks almost entirely
  // unscanned here. Merge Spotlight's per-host coverage in -- best-effort,
  // same pattern as the companies route's RBVM merge.
  if (elasticVulnEnabled()) {
    try {
      const db = await riskScoringDatabase();
      const hostsByCompany = await getScannedHostnamesByCompany(db, companyId);
      const companyNames = new Map(listCompanies().map((c) => [c.id, c.name]));
      mergeSpotlightCoverage(coverage, hostsByCompany, companyNames);
    } catch (err) {
      console.error("[coverage] could not merge Spotlight host coverage:", err instanceof Error ? err.message : err);
    }
  }
  return NextResponse.json({ coverage });
}

function mergeSpotlightCoverage(
  coverage: AssetCoverage,
  hostsByCompany: Map<string, HostRiskRow[]>,
  companyNames: Map<string, string>,
): void {
  for (const [companyId, hosts] of hostsByCompany) {
    const byHostname = new Map(hosts.map((h) => [h.hostname.trim().toLowerCase(), h]));
    const applyHit = (row: CoverageRow): boolean => {
      if (row.companyId !== companyId) return false;
      const key = row.identifier.trim().toLowerCase();
      const hit = byHostname.get(key);
      if (!hit) return false;
      row.openFindings = Math.max(row.openFindings, hit.openFindings);
      row.worstRisk = Math.max(row.worstRisk, hit.worstRisk);
      byHostname.delete(key);
      return true;
    };

    for (const row of coverage.matched) applyHit(row);

    const stillUnscanned: CoverageRow[] = [];
    for (const row of coverage.knownNotScanned) {
      if (applyHit(row)) coverage.matched.push(row);
      else stillUnscanned.push(row);
    }
    coverage.knownNotScanned = stillUnscanned;

    // Spotlight hosts left over aren't in this company's known inventory --
    // same as a scanned-but-unknown asset from the legacy diff.
    const existingShadow = new Set(
      coverage.scannedNotKnown
        .filter((r) => r.companyId === companyId)
        .map((r) => r.identifier.trim().toLowerCase()),
    );
    for (const [key, host] of byHostname) {
      if (existingShadow.has(key)) continue;
      coverage.scannedNotKnown.push({
        identifier: host.hostname,
        companyId,
        companyName: companyNames.get(companyId) ?? "—",
        exposure: null,
        criticality: null,
        owner: null,
        source: null,
        openFindings: host.openFindings,
        worstRisk: host.worstRisk,
      });
    }
  }

  coverage.matched.sort((a, b) => b.worstRisk - a.worstRisk);
  coverage.scannedNotKnown.sort((a, b) => b.worstRisk - a.worstRisk);
  coverage.summary = {
    known: coverage.matched.length + coverage.knownNotScanned.length,
    scanned: coverage.matched.length + coverage.scannedNotKnown.length,
    matched: coverage.matched.length,
    knownNotScanned: coverage.knownNotScanned.length,
    scannedNotKnown: coverage.scannedNotKnown.length,
  };
}
