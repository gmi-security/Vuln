import { createHash } from "node:crypto";
import { DashboardError } from "./elastic-dashboard";
import { resolveCustomerScope } from "./customer-scope";
import { readCustomerTopFixes } from "./customer-top-fixes";
import { applicationDatabase } from "./persist";
import { listFindings } from "./store";
import { storedSpotlightContext, storedSpotlightProof, reviewedPlatformFindings, recheckStoredSpotlightProof } from "./customer-stored-spotlight";
import { buildCustomerCveGroups, openCustomerFindings } from "./customer-cve-model";
import { persistManualCustomerGroups } from "./customer-cve-service";
import type { RemediationEvidence } from "./remediation-ticket-model";
import { remediationTicket } from "./remediation-ticket-packet";
import { remediationVariantId } from "./patch-recommendations";
import { SPOTLIGHT_SUMMARY_VERSION, matchesSpotlightTenant } from "./spotlight-summary-model";
import type { PatchGroup } from "./patch-request";

export async function prepareRemediationTicket(companyId:string,id:unknown,actor:string) {
  if(typeof id!=="string" || !id || id.length>250)throw new DashboardError("Choose a remediation from this customer's worklist.",400);
  const {company}=await resolveCustomerScope(companyId),worklist=await readCustomerTopFixes(companyId);
  const row=worklist.remediationWorklist?.rows.find(row=>row.id===id);
  if(!row)throw new DashboardError("This remediation is no longer in the customer's current worklist. Refresh and select it again.",409);
  const context=await storedSpotlightContext(companyId),db=applicationDatabase();
  if(!db)throw new DashboardError("Source database is unavailable.",503);
  const client=await db.connect();let proof:Awaited<ReturnType<typeof storedSpotlightProof>>=null,groups:PatchGroup[],runId:string|null=null;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout='5s'");
    await client.query("SET LOCAL lock_timeout='1s'");
    const installed=(await client.query("SELECT to_regclass('public.spotlight_import_current') IS NOT NULL AS installed")).rows[0]?.installed;
    const generation=installed ? (await client.query("SELECT run_id,promoted_at FROM spotlight_import_current WHERE tenant_key=$1",[companyId])).rows[0] : null;
    runId=generation?.run_id ?? null;
    if(row.source==="crowdstrike") {
      if(!runId)throw new DashboardError("A completed CrowdStrike import is required.",409);
      proof=await storedSpotlightProof(client,context,companyId,runId);
      // Only the selected action leaves SQL. Raw findings never enter this request.
      const saved=(await client.query(`SELECT summary->'patchActions'->($4::text) AS evidence,summary->>'patchEvidenceError' AS evidence_error,summary->'vendorScope' AS vendor_scope,source_rows
        FROM spotlight_summary_generations WHERE company_id=$1 AND run_id=$2 AND model_version=$3`,[companyId,runId,SPOTLIGHT_SUMMARY_VERSION,id])).rows[0];
      const evidence=saved?.evidence as RemediationEvidence|undefined;
      if(saved?.evidence_error)throw new DashboardError(saved.evidence_error,413);
      if(!evidence)throw new DashboardError("Ticket evidence is being prepared by the summary worker. Try again when the summary finishes; no source re-import is needed.",409);
      const cid=proof?.cid ?? saved.vendor_scope?.tenantId;
      if(!matchesSpotlightTenant(saved.vendor_scope,cid,saved.source_rows) || evidence.id!==id ||
          id!==`crowdstrike:${cid}:${remediationVariantId(evidence.remediation)}` || evidence.hosts.some(h=>h.cid!==cid))
        throw new DashboardError("The remediation does not match the customer's approved source.",409);
      const group=remediationTicket(company,evidence,new Date(generation.promoted_at).toISOString());
      if(proof)group.storedSpotlightScope=proof;
      groups=[group];
    } else {
      const findings=reviewedPlatformFindings(openCustomerFindings(companyId,listFindings({companyId}),row.cves[0]),context,Boolean(runId)).filter(f=>{
        const key=JSON.stringify([f.cve.toUpperCase(),(f.remediation || "").trim().replace(/\s+/g," ").toLowerCase()]);
        return createHash("sha256").update(`${companyId}\0${key}`).digest("hex").slice(0,32)===id;
      });
      groups=buildCustomerCveGroups(company,row.cves[0],findings,[],new Set(),new Date().toISOString());
    }
    if(groups.reduce((n,g)=>n+g.findingCount,0)!==row.findingCount || new Set(groups.flatMap(g=>g.hostScope)).size!==row.deviceCount ||
        JSON.stringify([...new Set(groups.flatMap(g=>g.cves))].sort())!==JSON.stringify([...row.cves].sort()))
      throw new DashboardError("The remediation evidence changed. Refresh the worklist before preparing the full request.",409);
    await client.query("COMMIT");
  }catch(error){await client.query("ROLLBACK").catch(()=>{});throw error;}finally{client.release();}
  async function recheck() {
    await recheckStoredSpotlightProof(proof);
    if(row?.source==="crowdstrike" && (await db!.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1",[companyId])).rows[0]?.run_id!==runId)
      throw new DashboardError("The source import changed. Refresh the worklist and prepare the current evidence.",409);
  }
  await recheck();
  if(!proof && JSON.stringify(await storedSpotlightContext(companyId))!==JSON.stringify(context))throw new DashboardError("Customer source approval changed. Refresh the worklist.",409);
  const saved=await persistManualCustomerGroups(companyId,groups,actor,true);
  await recheck();
  return {companyId,groups:saved.map(({id,group})=>({id,cves:group.cves.length,devices:group.deviceCount})),reviewUrl:`/remediation?companyId=${encodeURIComponent(companyId)}&view=tickets`};
}
