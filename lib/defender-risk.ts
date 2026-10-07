import { ensureHydrated,listFindings,listAssets,defenderProjectedRun } from "./store";
import { defenderStore } from "./defender-store";
import { calculateRiskScore,calculateSwath,type RiskScoreInput } from "./risk-scoring";
import { getCveEnrichment,getRiskConfig,riskScoringDatabase,upsertFindingRiskBatch,recordRiskSnapshot,type UpsertFindingRiskInput } from "./risk-scoring-store";
import { refreshCveEnrichment } from "./cve-enrichment-refresh";
import { patchTicketDatabase } from "./patch-ticket-store";
import type { Finding,InventoryAsset } from "./types";

export function defenderRiskInput(f: Finding, asset?: InventoryAsset,
  enrichment?: Awaited<ReturnType<typeof getCveEnrichment>> extends Map<string,infer V> ? V : never): RiskScoreInput {
  return { cve:f.cve,cvss:f.cvss > 0 ? f.cvss : f.defender?.cvss ?? enrichment?.cvssScore ?? null,
    epssProbability:enrichment?.epssProbability ?? null,epssPercentile:enrichment?.epssPercentile ?? null,
    cisaKev:enrichment?.cisaKev ?? f.kev,knownExploit:f.exploitAvailable,
    activeExploitation:enrichment?.activeExploitation ?? false,ransomwareAssociation:enrichment?.kevRansomware ?? f.ransomware,
    publishedAt:enrichment?.publishedDate ?? null,patchAvailable:null,repeatedDetection:false,widespreadExposure:false,
    internetExposed:f.assetExposure === "Internet-facing",assetCriticality:f.assetCriticality,
    assetType:asset?.os && /windows (10|11)|macos/i.test(asset.os) ? "workstation" : "other",
    production:false,healthcareIomt:false,criticalBusinessApp:false,clientDesignatedCritical:f.assetCriticality === "Crown Jewel" };
}

export async function refreshDefenderRisk(enrich = true) {
  await ensureHydrated();
  const companies = (await defenderStore().list()).filter(c=>c.currentRun);
  if (!companies.length) return { findingsScored:0,errors:0 };
  const db = await riskScoringDatabase(), config = await getRiskConfig(db);
  let findingsScored = 0, errors = 0;
  for (const company of companies) {
    try {
      if (defenderProjectedRun(company.companyId) !== company.currentRun) throw new Error("Defender publication is still pending.");
      const rows = listFindings({companyId:company.companyId}).filter(f=>f.defender);
      const cves = [...new Set(rows.map(f=>f.cve))];
      if (enrich) errors += (await refreshCveEnrichment(cves)).errors;
      const enriched = await getCveEnrichment(db,cves);
      const inventory = new Map(listAssets({companyId:company.companyId}).filter(a=>a.defenderDeviceId).map(a=>[a.defenderDeviceId!,a]));
      const tenantKey = `defender:${company.companyId}`;
      // Exact ticket device/CVE coverage; a ticket for one host must not cover
      // every device with the same CVE. Read the patch DB separately (it may
      // be configured in a different physical database).
      const cw = await patchTicketDatabase();
      const tickets = (await cw.query(`SELECT packet->'deviceCves' AS scope,closed FROM patch_group_ticket_requests
        WHERE tenant_id=$1 AND packet->>'source'='stored-findings' AND state='created'`,[company.companyId])).rows;
      const covered = new Map<string,boolean>();
      for (const t of tickets) for (const p of t.scope ?? []) if (p.cid === company.companyId)
        covered.set(JSON.stringify([p.hostId,p.cve]),(covered.get(JSON.stringify([p.hostId,p.cve])) ?? true) && t.closed);
      const inputs: UpsertFindingRiskInput[] = rows.map(f=> {
        const input = defenderRiskInput(f,inventory.get(f.defender!.deviceId),enriched.get(f.cve));
        const score = calculateRiskScore(input,config.weights), swath = calculateSwath(input,score.total,config.swathThresholds);
        const closed = covered.get(JSON.stringify([f.asset,f.cve]));
        return { tenantKey,companyId:f.companyId,cve:f.cve,hostKey:f.asset,hostname:inventory.get(f.defender!.deviceId)?.hostname ?? f.asset,
          severity:f.severity,riskScore:score.total,technicalScore:score.technical,exploitLikelihoodScore:score.exploitLikelihood,
          threatActivityScore:score.threatActivity,assetContextScore:score.assetContext,additionalContextScore:score.additionalContext,
          reasons:["Source: Microsoft Defender",...score.reasons],calculatedSwath:swath.calculatedSwath,effectiveSwath:swath.effectiveSwath,
          epssProbability:input.epssProbability,epssPercentile:input.epssPercentile,cisaKev:input.cisaKev,knownExploit:input.knownExploit,
          activeExploitation:input.activeExploitation,ransomwareAssociation:input.ransomwareAssociation,internetExposed:input.internetExposed,
          assetCriticality:input.assetCriticality,sourceReappeared:f.defender!.active,
          verificationStatus:f.status === "Resolved" && !f.defender!.active ? "verified_remediated" : closed === undefined ? "detected" : closed ? "pending_verification" : "ticket_created" };
      });
      // Publish one customer's scores and active membership atomically. Never
      // retire yesterday's scores because today's write stopped halfway.
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1,804232))",[tenantKey]);
        for (let i=0;i<inputs.length;i+=2000) await upsertFindingRiskBatch(client,tenantKey,inputs.slice(i,i+2000));
        const open = rows.filter(f=>["Open","In Remediation"].includes(f.status)).map(f=>({cve:f.cve,host:f.asset}));
        await client.query(`UPDATE finding_risk f SET source_open=(f.cve,f.host_key) IN (SELECT cve,host FROM jsonb_to_recordset($2::jsonb) x(cve TEXT,host TEXT)) WHERE tenant_key=$1`,[tenantKey,JSON.stringify(open)]);
        if (defenderProjectedRun(company.companyId) !== company.currentRun) throw new Error("A newer Defender generation was published during scoring.");
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
      findingsScored += inputs.length;
      await recordRiskSnapshot(db,company.companyId);
    } catch { errors++; console.error("[defender] Risk refresh failed; retry on the next scheduled pass."); }
  }
  return {findingsScored,errors};
}
