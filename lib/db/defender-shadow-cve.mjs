// Offline CVE detail boundary. No runtime routes, source calls or ticket persistence.
import {shadowReadRequest} from './defender-shadow-reads.mjs';
import {reconstructShadowSql} from './defender-platform-shadow.mjs';
export const MAX_SHADOW_CVE_FINDINGS=10000;
export const MAX_SHADOW_CVE_BYTES=32*1024*1024;
const fail=(message,status)=>{throw Object.assign(new Error(message),{status});};
export function shadowCveRequest(request){
  const {companyId,projectionId}=shadowReadRequest({companyId:request.companyId,projectionId:request.projectionId});
  if(typeof request.cve!=='string'||!/^CVE-\d{4}-\d{4,19}$/i.test(request.cve))fail('A valid CVE is required',400);
  return {companyId,projectionId,cve:request.cve.toUpperCase()};
}

export async function readDefenderShadowCve(client,request){
  const {companyId,projectionId,cve}=shadowCveRequest(request),scope=[companyId,projectionId],started=Date.now();
  const deadline=()=>{if(Date.now()-started>60000)fail('CVE detail read deadline exceeded',503);};
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s';SET LOCAL idle_in_transaction_session_timeout='15s';SET LOCAL lock_timeout='2s'");
    const {rows:[generation]}=await client.query(`SELECT state,model_version,source_run,snapshot_saved_at
      FROM defender_shadow_generations WHERE company_id=$1 AND projection_id=$2`,scope);
    if(generation?.state!=='verified'||generation.model_version!==2)fail('Verified version-2 customer projection required',409);
    const {rows:identities}=await client.query(`SELECT f.finding_id FROM defender_shadow_findings f
      JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
      JOIN defender_shadow_assessments a USING(company_id,projection_id,finding_id)
      WHERE f.company_id=$1 AND f.projection_id=$2 AND upper(f.issue_key)=$3
        AND w.status IN ('Open','In Remediation') AND f.connector NOT IN ('spiderfoot','artemis')
      ORDER BY a.real_risk DESC,a.cvss DESC,f.legacy_order LIMIT 10001`,[...scope,cve]);
    if(identities.length>MAX_SHADOW_CVE_FINDINGS)fail('CVE exceeds 10000 findings; no partial request',413);
    if(!identities.length)fail('No open findings for this customer and CVE',404);
    const ids=identities.map(r=>r.finding_id);
    if(new Set(ids).size!==ids.length)fail('Duplicate CVE finding identities',409);
    const sql=reconstructShadowSql+' AND f.finding_id=ANY($3::text[])';
    // Measure in PostgreSQL before transferring full remediation/evidence payloads.
    const {rows:[size]}=await client.query(`SELECT count(*)::int n,COALESCE(sum(octet_length(record::text)),0)::text bytes FROM (${sql}) selected`,[...scope,ids]);
    if(size.n!==ids.length)fail('CVE evidence is incomplete',409);
    if(Number(size.bytes)+size.n+2>MAX_SHADOW_CVE_BYTES)fail('CVE evidence exceeds 32 MiB; no partial request',413);
    deadline();
    const byId=new Map();let bytes=2;
    for(let offset=0;offset<ids.length;offset+=500){
      deadline();const {rows}=await client.query(sql,[...scope,ids.slice(offset,offset+500)]);
      for(const {id,record} of rows){
        if(record?.id!==id||byId.has(id)||record.companyId!==companyId||record.cve?.toUpperCase()!==cve||
          !['Open','In Remediation'].includes(record.status)||['spiderfoot','artemis'].includes(record.connector))fail('CVE evidence scope mismatch',409);
        bytes+=Buffer.byteLength(JSON.stringify(record),'utf8')+1;
        if(bytes>MAX_SHADOW_CVE_BYTES)fail('CVE evidence exceeds 32 MiB; no partial request',413);
        byId.set(id,record);
      }
    }
    if(byId.size!==ids.length||ids.some(id=>!byId.has(id)))fail('CVE evidence is incomplete',409);
    const findings=ids.map(id=>byId.get(id));
    const observedAt=findings.reduce((latest,f)=>f.lastSeen>latest?f.lastSeen:latest,'');
    const hosts=findings.slice(0,50).map(f=>({host:f.defender?.hostname||f.asset,
      source:f.connector,severity:f.severity,cvss:f.cvss,risk:f.realRisk}));
    deadline();await client.query('COMMIT');
    return {scope:'published-defender-cohort',companyId,projectionId,projectionModelVersion:2,cve,
      sourceRun:generation.source_run,snapshotSavedAt:generation.snapshot_saved_at,observedAt,
      findingCount:findings.length,deviceCount:new Set(findings.map(f=>JSON.stringify([companyId,f.asset]))).size,
      hosts,findings};
  }catch(error){await client.query('ROLLBACK');throw error;}
}
