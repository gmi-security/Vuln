import {readCustomerTopFixes} from "./customer-top-fixes";
import {withFixTicketStatus} from "./customer-fix-ticket-status";
import {applicationDatabase} from "./persist";
import {DashboardError} from "./elastic-dashboard";
import type {Pool} from "pg";
export async function customerPatchPriority(companyId:unknown,tickets:()=>Pick<Pool,"connect">,signal?:AbortSignal) {
  signal?.throwIfAborted();
  if(typeof companyId!=="string"||!companyId||companyId.length>100)throw new DashboardError("Choose an existing customer.",400);
  const db=applicationDatabase();if(!db)throw new DashboardError("Priority worklist storage is unavailable.",503);
  async function currentRun(){const client=await db!.connect();try{
    await client.query("BEGIN READ ONLY");await client.query("SET LOCAL statement_timeout='3s'");await client.query("SET LOCAL lock_timeout='500ms'");
    const installed=(await client.query("SELECT to_regclass('public.spotlight_import_current') IS NOT NULL AS installed")).rows[0]?.installed;
    const run=installed?(await client.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1",[companyId])).rows[0]?.run_id??null:null;
    await client.query("COMMIT");return run;
  }catch(error){await client.query("ROLLBACK").catch(()=>{});throw error;}finally{client.release();}}
  const before=await currentRun();
  const data=await readCustomerTopFixes(companyId,undefined,true,signal),priority=data.priorityWorklist!;
  const after=await currentRun();
  if(before!==after)throw new DashboardError("The source import changed. Refresh the worklist.",409);
  signal?.throwIfAborted();
  const overlay=await withFixTicketStatus(db,{...data,rows:priority.byCve.map(r=>({...r,cve:r.cves[0],maxRisk:0})),
    remediationWorklist:{totalGroups:priority.totalRemediations,limit:50,rows:priority.byRemediation.map(r=>({...r,maxRisk:0,grouping:r.source==="crowdstrike"?"vendor-remediation":"single-cve"}))}},after,tickets);
  if(after!==await currentRun())throw new DashboardError("The source import changed. Refresh the worklist.",409);
  signal?.throwIfAborted();
  return {companyId:data.companyId,calculatedAt:data.calculatedAt,...priority,
    byCve:priority.byCve.map(r=>({...r,ticketStatus:overlay.rows.find(x=>x.id===r.id)?.ticketStatus})),
    byRemediation:priority.byRemediation.map(r=>({...r,ticketStatus:overlay.remediationWorklist?.rows.find(x=>x.id===r.id)?.ticketStatus}))};
}
