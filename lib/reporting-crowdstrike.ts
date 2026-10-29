import { applicationDatabase } from "./persist";
import { storedSpotlightContext, storedSpotlightProof, recheckStoredSpotlightProof } from "./customer-stored-spotlight";
import { matchesSpotlightTenant, SPOTLIGHT_SUMMARY_VERSION } from "./spotlight-summary-model";
import { createSpotlightSummaryStore } from "./spotlight-summary-store";
import type { ReportingCrowdstrike } from "./customer-source-read-model";


// Use the same customer/generation authority as CVE details and Top fixes.
// Only bounded metadata and saved CVE summaries are read. No provider calls,
// source-row hydration, imports, summary builds or legacy count addition.
export async function reportingCrowdstrike(companyId: string): Promise<ReportingCrowdstrike | null> {
  const unavailable: ReportingCrowdstrike = { state: "unavailable",
    message: "The customer's completed CrowdStrike summary could not be verified. Current counts are unavailable; check its connector assignment and summary status." };
  try {
    const context = await storedSpotlightContext(companyId), db = applicationDatabase();
    if (!db) return context.route ? unavailable : null;
    const client = await db.connect();
    let runId: string | null = null, cid: string | undefined;
    let proof: Awaited<ReturnType<typeof storedSpotlightProof>> = null;
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='5s'");
      await client.query("SET LOCAL lock_timeout='1s'");
      const tables = (await client.query("SELECT to_regclass('public.spotlight_import_current') AS imports, to_regclass('public.spotlight_summary_generations') AS summaries")).rows[0];
      if (tables?.imports) runId = (await client.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1", [companyId])).rows[0]?.run_id ?? null;
      if (runId) {
        proof = await storedSpotlightProof(client, context, companyId, runId);
        const saved = tables?.summaries ? (await client.query(
          "SELECT summary->'vendorScope' AS vendor_scope,source_rows FROM spotlight_summary_generations WHERE company_id=$1 AND run_id=$2 AND model_version=$3",
          [companyId, runId, SPOTLIGHT_SUMMARY_VERSION])).rows[0] : null;
        if (saved) {
          cid = proof?.cid ?? saved.vendor_scope?.tenantId;
          if (!cid || !matchesSpotlightTenant(saved.vendor_scope, cid, saved.source_rows)) throw new Error("Unverified saved source scope");
        }
      }
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK").catch(() => {}); throw error; }
    finally { client.release(); }
    if (!runId) return context.route ? unavailable : null;
    if (!cid) return {state:"unavailable",message:"Waiting for the completed CrowdStrike import's summary. Current counts are unavailable."};
    const result = await createSpotlightSummaryStore(db).read({ companyId, spotlightTenant: cid,
      now: new Date(), staleAfterMs: 36 * 3600000, offset: 0, limit: 50 });
    if (result.companyId !== companyId || result.source !== "crowdstrike" ||
        (result.state === "available" && result.generation.id !== runId)) return unavailable;
    await recheckStoredSpotlightProof(proof);
    if (!proof && JSON.stringify(await storedSpotlightContext(companyId)) !== JSON.stringify(context)) return unavailable;
    const latest = (await db.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1", [companyId])).rows[0]?.run_id ?? null;
    return latest === runId ? result : unavailable;
  } catch { return unavailable; }
}
