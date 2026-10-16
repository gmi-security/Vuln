import type {Pool,PoolClient} from "pg";
import type {TopFixesResult} from "./reporting-top-fixes";
import {fixTicketStatus,ticketMatchesFix,type FixTicket,type TicketScope,type FixEvidence,type FixTicketStatus} from "./fix-ticket-status";

// Optional workflow overlay. Failure must never remove the vulnerability rows
// or turn an unknown ticket lookup into "no ticket". No provider calls or DDL.
export async function withFixTicketStatus(db:Pick<Pool,"connect">,result:TopFixesResult,runId:string|null,ticketDatabase:()=>Pick<Pool,"connect">):Promise<TopFixesResult> {
  const rows=[...result.rows,...(result.remediationWorklist?.rows??[])];
  const cves=[...new Set(rows.flatMap(row=>"cves" in row ? row.cves:[row.cve]))];
  const apply=(status:(row:typeof rows[number])=>FixTicketStatus)=>({...result,rows:result.rows.map(row=>({...row,ticketStatus:status(row)})),
    ...(result.remediationWorklist?{remediationWorklist:{...result.remediationWorklist,rows:result.remediationWorklist.rows.map(row=>({...row,ticketStatus:status(row)}))}}:{})});
  let client:PoolClient|undefined;
  try {
    client=await ticketDatabase().connect();
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout='3s'");
    await client.query("SET LOCAL lock_timeout='500ms'");
    // Limit records AND bytes before transferring metadata or scope to Node.
    const found=await client.query(`WITH candidates AS (
      SELECT updated_at,id,jsonb_build_object('id',id,'kind','group','companyId',packet->>'appCompanyId','tenantId',tenant_id,'remediationId',remediation_id,
        'vendorRemediationId',packet->>'vendorRemediationId','title',COALESCE(packet->>'title',''),'action',COALESCE(packet->>'action',''),
        'reference',COALESCE(packet->>'reference',''),'link',COALESCE(packet->>'link',''),'vendorUrl',COALESCE(packet->>'vendorUrl',''),
        'published',COALESCE(packet->>'published',''),'connectors',packet->'connectors','cves',cves,'state',state,'reviewState',review_state,
        'ticketId',ticket_id,'ticketUrl',ticket_url,'closed',closed) AS meta
      FROM patch_group_ticket_requests WHERE packet->>'appCompanyId'=$1 AND cves ?| $2::text[]
        AND (review_state<>'dismissed' OR ticket_id IS NOT NULL)
        AND (cw_target IS NULL OR cw_target=(SELECT target FROM patch_connectwise_connection WHERE id=1))
      UNION ALL
      SELECT updated_at,id,jsonb_build_object('id',id,'kind','single','companyId',packet->>'appCompanyId','cves',jsonb_build_array(cve),
        'state',state,'reviewState','pending','ticketId',ticket_id,'ticketUrl',ticket_url,'closed',closed) AS meta
      FROM patch_ticket_requests WHERE packet->>'appCompanyId'=$1 AND cve=ANY($2::text[])
        AND (cw_target IS NULL OR cw_target=(SELECT target FROM patch_connectwise_connection WHERE id=1))
    ), matches AS (
      SELECT meta FROM candidates ORDER BY updated_at DESC,id LIMIT 501
    ) SELECT CASE WHEN sum(octet_length(meta::text)) OVER ()<=8388608 THEN meta END AS meta FROM matches`,[result.companyId,cves]);
    if(found.rows.length>500 || found.rows.some(row=>!row.meta))throw Error("Ticket status capacity exceeded");
    const records=found.rows.map(row=>row.meta) as FixTicket[];
    const current=(result.remediationWorklist?.rows??[]).filter(row=>row.source==="crowdstrike" &&
      records.some(t=>t.ticketId && !t.closed && ticketMatchesFix(result.companyId,row,t)));
    let evidence:FixEvidence[]=[],scopes:TicketScope[]=[];
    if(current.length && runId) {
      const ids=records.filter(t=>t.ticketId && !t.closed && current.some(row=>ticketMatchesFix(result.companyId,row,t))).map(t=>t.id);
      const savedScopes=await client.query(`WITH selected AS (
        SELECT id,jsonb_build_object('id',id,'coverage',packet->'deviceCveCoverage','devices',packet->'deviceCves') AS scope
        FROM patch_group_ticket_requests WHERE id=ANY($1::uuid[]) AND packet->>'appCompanyId'=$2
      ) SELECT CASE WHEN sum(octet_length(scope::text)) OVER ()<=8388608 THEN scope END AS scope FROM selected`,[ids,result.companyId]);
      scopes=savedScopes.rows.filter(row=>row.scope).map(row=>row.scope);
    }
    await client.query("COMMIT");
    client.release();client=undefined;
    // Ticket storage may have its own database. Release it before opening the
    // source snapshot, including when both use one pool with just one slot.
    if(current.length && runId) {
      client=await db.connect();
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='3s'");
      await client.query("SET LOCAL lock_timeout='500ms'");
      const saved=await client.query(`WITH selected AS (
        SELECT a.key AS id,a.value->'coverage' AS coverage,(a.value->>'findingCount')::bigint AS findings
        FROM spotlight_summary_generations g JOIN spotlight_import_current c ON c.tenant_key=g.company_id AND c.run_id=g.run_id
        CROSS JOIN LATERAL jsonb_each(g.summary->'patchActions') a
        WHERE g.company_id=$1 AND g.run_id=$2 AND g.model_version=6 AND a.key=ANY($3::text[])
      ) SELECT id,findings,CASE WHEN sum(octet_length(coverage::text)) OVER ()<=8388608 THEN coverage END AS coverage FROM selected`,[result.companyId,runId,current.map(row=>row.id)]);
      evidence=saved.rows.filter(row=>row.coverage).map(row=>({id:row.id,coverage:row.coverage,findingCount:Number(row.findings)}));
      await client.query("COMMIT");
    }
    const budget={remaining:1_000_000};
    return apply(row=>fixTicketStatus(result.companyId,row,records,scopes,evidence.find(e=>e.id===row.id),budget));
  }catch{
    await client?.query("ROLLBACK").catch(()=>{});
    return apply(()=>({state:"unavailable",tickets:[],more:0}));
  }finally{client?.release();}
}
