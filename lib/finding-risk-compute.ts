import { classifyAsset } from "./threat";
import { calculateRiskScore, calculateSwath, type AssetType, type RiskScoreInput } from "./risk-scoring";
import { getCveEnrichment, getRiskConfig, riskScoringDatabase, upsertFindingRisk } from "./risk-scoring-store";
import { listCompletedSpotlightRecords, type SpotlightRecord } from "./spotlight-record-store";
import { patchTicketDatabase } from "./patch-ticket-store";

// ponytail: host identity is hostname (falling back to local IP) from the
// CURRENT Spotlight generation. CrowdStrike's own device AID would be a
// truer stable key, but it isn't on SpotlightRecord today -- upgrade path is
// to thread aid through parseSpotlightResource -> SpotlightRecord -> here.
function hostKeyFor(record: SpotlightRecord): string {
  return (record.hostname || record.localIp || record.sourceId).toLowerCase().trim();
}

function extractCvss(record: SpotlightRecord): number | null {
  const raw = record.raw as { cve?: { cvss_v3?: number; cvss_v2?: number; exploit_status?: number; published_date?: string } } | undefined;
  const v = Number(raw?.cve?.cvss_v3 ?? raw?.cve?.cvss_v2);
  return Number.isFinite(v) ? v : null;
}

function extractKnownExploit(record: SpotlightRecord): boolean {
  const raw = record.raw as { cve?: { exploit_status?: number } } | undefined;
  return Boolean(raw?.cve?.exploit_status);
}

function extractPublishedAt(record: SpotlightRecord): string | null {
  const raw = record.raw as { cve?: { published_date?: string } } | undefined;
  return raw?.cve?.published_date ?? null;
}

function inferAssetType(hostname: string, criticality: "Crown Jewel" | "High" | "Normal" | "Low"): AssetType {
  const h = hostname.toLowerCase();
  if (/\bdc\d*\b|-dc\b/.test(h)) return "domain_controller";
  if (/\b(adfs|idp|okta|sso|ldap|azuread)\b/.test(h)) return "identity";
  if (criticality === "Low" || /\bws-|wks\b/.test(h)) return "workstation";
  return "server";
}

async function ticketCoverageByCve(tenantKey: string): Promise<Map<string, { ticketId: number | null; closed: boolean; fixVerifiedState: string | null }>> {
  // ponytail: scoped to CVE, not CVE+specific host -- a ticket covering this
  // CVE for the tenant marks every matching finding as covered, even if its
  // hostScope was narrower. Upgrade path: index patch_group_ticket_requests
  // by (tenant, cve, host) once ticket volume makes the approximation costly.
  const db = await patchTicketDatabase();
  const rows = (await db.query(
    "SELECT cves, ticket_id, closed, fix_verified_state FROM patch_group_ticket_requests WHERE tenant_id=$1 AND state='created'",
    [tenantKey],
  )).rows as { cves: string[]; ticket_id: number | null; closed: boolean; fix_verified_state: string | null }[];
  const map = new Map<string, { ticketId: number | null; closed: boolean; fixVerifiedState: string | null }>();
  for (const row of rows) {
    for (const cve of row.cves ?? []) {
      const existing = map.get(cve);
      // If multiple tickets cover the same CVE for this tenant, prefer the
      // most-advanced state (verified > closed-pending > open) so the
      // derived status doesn't regress based on row ordering.
      const rank = (r?: typeof existing) => !r ? -1 : r.fixVerifiedState === "verified" ? 3 : r.closed ? 2 : 1;
      const candidate = { ticketId: row.ticket_id, closed: row.closed, fixVerifiedState: row.fix_verified_state };
      if (rank(candidate) > rank(existing)) map.set(cve, candidate);
    }
  }
  return map;
}

// Derived, not a new redundant column: verification_status reads directly
// off the existing closed/fix_verified_state fields that
// lib/group-closure-validation.ts already maintains (see that file for the
// real "don't trust a closure until CrowdStrike confirms it" logic). This
// function only labels what's already there for the RBVM UI.
function deriveVerificationStatus(coverage?: { ticketId: number | null; closed: boolean; fixVerifiedState: string | null }): string {
  if (!coverage || !coverage.ticketId) return "detected";
  if (coverage.fixVerifiedState === "verified") return "verified_remediated";
  if (coverage.closed) return "pending_verification";
  if (coverage.fixVerifiedState === "still_open") return "reopened";
  return "ticket_created";
}

export type ComputeResult = { tenantKey: string; findingsScored: number; distinctCves: number; errors: number };

// One tenant's full pass: read its current Spotlight generation, enrich each
// finding against cve_enrichment (already-refreshed KEV/EPSS), infer asset
// context, score, and upsert finding_risk. Call refreshCveEnrichment with
// this tenant's CVE set BEFORE this, so scores reflect current KEV/EPSS --
// this function only reads cve_enrichment, it never fetches externally
// itself (keeps page-render-adjacent calls out of the network path).
export async function computeFindingRiskForTenant(tenantKey: string, companyId: string): Promise<ComputeResult> {
  const riskDb = await riskScoringDatabase();
  const { weights, swathThresholds } = await getRiskConfig(riskDb);
  const coverage = await ticketCoverageByCve(tenantKey);

  let offset = 0, findingsScored = 0, errors = 0;
  const distinctCves = new Set<string>();
  const allCves = new Set<string>();
  const batch: SpotlightRecord[] = [];
  do {
    batch.length = 0;
    batch.push(...await listCompletedSpotlightRecords(tenantKey, 1000, offset));
    for (const r of batch) allCves.add(r.cve.toUpperCase());
    offset += batch.length;
  } while (batch.length === 1000);

  const enrichment = await getCveEnrichment(riskDb, Array.from(allCves));

  offset = 0;
  let page: SpotlightRecord[] = [];
  do {
    page = await listCompletedSpotlightRecords(tenantKey, 1000, offset);
    for (const record of page) {
      try {
        const cve = record.cve.toUpperCase();
        const enriched = enrichment.get(cve);
        const { exposure, criticality } = classifyAsset(record.hostname || record.localIp || "");
        const assetType = inferAssetType(record.hostname, criticality);
        const input: RiskScoreInput = {
          cve, cvss: extractCvss(record) ?? enriched?.cvssScore ?? null,
          epssProbability: enriched?.epssProbability ?? null, epssPercentile: enriched?.epssPercentile ?? null,
          cisaKev: enriched?.cisaKev ?? false, knownExploit: extractKnownExploit(record),
          activeExploitation: false, // no independent active-exploitation feed wired up yet -- see report
          ransomwareAssociation: enriched?.kevRansomware ?? false,
          publishedAt: extractPublishedAt(record) ?? enriched?.publishedDate ?? null,
          patchAvailable: null, repeatedDetection: false, widespreadExposure: false,
          internetExposed: exposure === "Internet-facing", assetCriticality: criticality, assetType,
          production: criticality === "Crown Jewel" || criticality === "High",
          healthcareIomt: false, criticalBusinessApp: false, clientDesignatedCritical: false,
        };
        const score = calculateRiskScore(input, weights);
        const swath = calculateSwath(input, score.total, swathThresholds);
        await upsertFindingRisk(riskDb, {
          tenantKey, companyId, cve, hostKey: hostKeyFor(record), hostname: record.hostname, severity: record.severity,
          riskScore: score.total, technicalScore: score.technical, exploitLikelihoodScore: score.exploitLikelihood,
          threatActivityScore: score.threatActivity, assetContextScore: score.assetContext, additionalContextScore: score.additionalContext,
          reasons: score.reasons, calculatedSwath: swath.calculatedSwath, effectiveSwath: swath.effectiveSwath,
          epssProbability: input.epssProbability, epssPercentile: input.epssPercentile, cisaKev: input.cisaKev,
          knownExploit: input.knownExploit, activeExploitation: input.activeExploitation, ransomwareAssociation: input.ransomwareAssociation,
          internetExposed: input.internetExposed, assetCriticality: input.assetCriticality,
          verificationStatus: deriveVerificationStatus(coverage.get(cve)),
        });
        findingsScored++; distinctCves.add(cve);
      } catch {
        errors++; // one malformed record must not abort the whole tenant's pass
      }
    }
    offset += page.length;
  } while (page.length === 1000);

  return { tenantKey, findingsScored, distinctCves: distinctCves.size, errors };
}
