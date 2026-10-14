import { DashboardError } from "./elastic-dashboard";
import { applicationDatabase } from "./persist";
import { customerTopFixes, ensureHydrated, getCompanyIdentity } from "./store";
import { storedSpotlightContext, storedSpotlightProof, recheckStoredSpotlightProof, reviewedPlatformFinding } from "./customer-stored-spotlight";
import { matchesSpotlightTenant, SPOTLIGHT_SUMMARY_VERSION } from "./spotlight-summary-model";
import type { TopFixesResult, TopFix } from "./reporting-top-fixes";

function savedFixes(value: TopFixesResult | undefined, companyId: string): TopFixesResult {
  const count=(n: unknown)=>typeof n === "number" && Number.isSafeInteger(n) && n>=0;
  if (!value || value.companyId!==companyId || ![value.totalFixes,value.affectedDevices,value.findingCount,value.uniqueCves,value.missingRemediation,value.missingDevice].every(count) ||
    value.limit!==50 || !Array.isArray(value.rows) || value.rows.length!==Math.min(50,value.totalFixes) ||
    value.rows.some(row=>!/^CVE-\d{4}-\d{4,19}$/.test(row.cve) || typeof row.id!=="string" || typeof row.remediation!=="string" || !row.remediation.trim() ||
      !count(row.deviceCount) || !count(row.findingCount) || !Number.isFinite(row.maxRisk) || row.deviceCount>row.findingCount || row.findingCount>value.findingCount ||
      row.deviceCount>value.affectedDevices)) throw new DashboardError("Saved CrowdStrike fix summary is inconsistent. Rebuild the source summary.",503);
  return value;
}

export async function readCustomerTopFixes(value: unknown): Promise<TopFixesResult> {
  if (typeof value!=="string" || !value || value.length>100) throw new DashboardError("Choose an existing customer.",400);
  await ensureHydrated();
  const company=getCompanyIdentity(value);
  if (!company || company.isDemo) throw new DashboardError("Customer not found.",404);
  const companyId=company.id, context=await storedSpotlightContext(companyId), db=applicationDatabase();
  if (!db) throw new DashboardError("Source database is unavailable.",503);
  const client=await db.connect();
  let runId: string | null=null, proof: Awaited<ReturnType<typeof storedSpotlightProof>>=null, spotlight: TopFixesResult | null=null;
  const notices: string[]=[];
  let installed=false;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout='5s'");
    await client.query("SET LOCAL lock_timeout='1s'");
    const tables=(await client.query("SELECT to_regclass('public.spotlight_import_current') AS imports, to_regclass('public.spotlight_summary_generations') AS summaries")).rows[0];
    installed=Boolean(tables?.imports);
    if (installed) runId=(await client.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1",[companyId])).rows[0]?.run_id ?? null;
    if (runId) {
      proof=await storedSpotlightProof(client,context,companyId,runId);
      const saved=tables.summaries ? (await client.query(`SELECT summary->'topFixes' AS fixes,summary->'vendorScope' AS vendor_scope,source_rows
        FROM spotlight_summary_generations WHERE company_id=$1 AND run_id=$2 AND model_version=$3`,[companyId,runId,SPOTLIGHT_SUMMARY_VERSION])).rows[0] : null;
      if (!saved) notices.push("CrowdStrike fixes are waiting for the completed-import summary. An operator must run the Spotlight summary worker; refreshing this page does not rebuild millions of source records.");
      else {
        const cid=proof?.cid ?? saved.vendor_scope?.tenantId;
        if (!matchesSpotlightTenant(saved.vendor_scope,cid,saved.source_rows)) throw new DashboardError("Saved CrowdStrike fix scope is inconsistent. Review the customer source and rebuild its summary.",409);
        spotlight=savedFixes(saved.fixes,companyId);
      }
    }
    await client.query("COMMIT");
  } catch (error) {await client.query("ROLLBACK").catch(()=>{});throw error;} finally {client.release();}
  // Same source authority as CVE details/patch preparation. Completed Spotlight
  // supersedes legacy RAM CrowdStrike findings, even when its summary is pending.
  const platform=await customerTopFixes(companyId,JSON.stringify([context,runId]),row=>reviewedPlatformFinding(row,context,Boolean(runId)));
  await recheckStoredSpotlightProof(proof);
  if (installed) {
    const current=(await db.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1",[companyId])).rows[0]?.run_id ?? null;
    if (current!==runId) throw new DashboardError("Source import changed while loading top fixes. Refresh to load the current results.",409);
  }
  if (!proof && JSON.stringify(await storedSpotlightContext(companyId))!==JSON.stringify(context)) throw new DashboardError("Customer source approval changed. Refresh to load current results.",409);
  const sources=[...(platform.findingCount || platform.missingRemediation ? ["Platform findings"] : []),...(spotlight ? ["Completed CrowdStrike import"] : [])];
  if (!spotlight) return {...platform,sources,notices,rows:platform.rows.map(row=>({...row,source:"platform"}))};
  const severity: Record<string,number>={Critical:4,High:3,Medium:2,Low:1,Info:0,Unknown:-1};
  const rows: TopFix[]=[...platform.rows.map(row=>({...row,source:"platform" as const})),...spotlight.rows.map(row=>({...row,source:"crowdstrike" as const}))];
  rows.sort((a,b)=>b.deviceCount-a.deviceCount || (severity[b.severity]??-1)-(severity[a.severity]??-1) ||
    (a.source??"").localeCompare(b.source??"") || b.maxRisk-a.maxRisk || b.findingCount-a.findingCount || a.id.localeCompare(b.id));
  return {...platform,calculatedAt:new Date().toISOString(),sources,notices,rows:rows.slice(0,50),
    totalFixes:platform.totalFixes+spotlight.totalFixes,affectedDevices:platform.affectedDevices+spotlight.affectedDevices,
    findingCount:platform.findingCount+spotlight.findingCount,uniqueCves:platform.uniqueCves+spotlight.uniqueCves,
    missingRemediation:platform.missingRemediation+spotlight.missingRemediation,missingDevice:platform.missingDevice+spotlight.missingDevice};
}
