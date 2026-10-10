import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase} from './defender-platform-shadow.mjs';
const fail=(message,status=409)=>{throw Object.assign(Error(message),{status});};
const statuses=['Open','In Remediation','Risk Accepted','False Positive','Resolved'];
const company=id=>typeof id==='string'&&/^CO-[A-Za-z0-9-]{1,98}$/.test(id);
const revision=value=>{const n=Number(value);if(!Number.isSafeInteger(n)||n<0)fail('Invalid workflow revision');return n;};
export function defenderWorkflowEditRequest(raw){
  if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(k=>!['companyId','findingId','projectionId','expectedRevision','patch','actor','reason'].includes(k)))fail('Invalid workflow request',400);
  if(!company(raw.companyId)||typeof raw.findingId!=='string'||!raw.findingId||raw.findingId.length>300||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(raw.projectionId??'')||
    !Number.isSafeInteger(raw.expectedRevision)||raw.expectedRevision<0||raw.expectedRevision>=Number.MAX_SAFE_INTEGER||
    typeof raw.actor!=='string'||!raw.actor.trim()||raw.actor.length>120||typeof raw.reason!=='string'||!raw.reason.trim()||raw.reason.length>500)fail('Explicit workflow scope, revision and audit context required',400);
  const p=raw.patch;
  if(!p||typeof p!=='object'||Array.isArray(p)||!Object.keys(p).length||Object.keys(p).some(k=>!['status','assignee'].includes(k))||
    (Object.hasOwn(p,'status')&&!statuses.includes(p.status))||
    (Object.hasOwn(p,'assignee')&&p.assignee!==null&&(typeof p.assignee!=='string'||p.assignee.length>200)))fail('Invalid workflow patch',400);
  return {...raw,patch:{...p,...(Object.hasOwn(p,'assignee')?{assignee:p.assignee?.trim()||null}:{})}};
}
export async function editDefenderWorkflow(client,raw,{beforeCommit}={}){
  const r=defenderWorkflowEditRequest(raw);await privateShadowDatabase(client,'target');await client.query('BEGIN');
  try{
    await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    await client.query('INSERT INTO defender_workflow_heads(company_id) VALUES($1) ON CONFLICT DO NOTHING',[r.companyId]);
    const head=(await client.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1 FOR UPDATE',[r.companyId])).rows[0];
    const old=(await client.query('SELECT * FROM defender_workflow_edits WHERE company_id=$1 AND finding_id=$2',[r.companyId,r.findingId])).rows[0];
    if(revision(old?.revision??0)!==r.expectedRevision)fail('Workflow changed. Reload before editing.');
    const basis=(await client.query(`SELECT f.issue_key cve,e.device_id,e.source_run,e.active,w.status,w.assignee,w.resolved_at
      FROM defender_shadow_generations g JOIN defender_shadow_findings f USING(company_id,projection_id)
      JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
      JOIN defender_shadow_evidence e USING(company_id,projection_id,finding_id)
      WHERE g.company_id=$1 AND g.projection_id=$2 AND f.finding_id=$3 AND g.state='verified'`,[r.companyId,r.projectionId,r.findingId])).rows[0];
    if(!basis)fail('Verified customer finding required',404);
    if(old&&(old.device_id!==basis.device_id||old.cve!==basis.cve))fail('Workflow finding identity changed');
    const patches=structuredClone(old?.patches??{}),now=(await client.query('SELECT clock_timestamp() at')).rows[0].at.toISOString();
    if(Object.hasOwn(r.patch,'status')&&r.patch.status!==(patches.status?.value??basis.status))patches.status={base:basis.status,baseResolvedAt:basis.resolved_at,
      value:r.patch.status,resolvedAt:['Resolved','False Positive'].includes(r.patch.status)?now:null,sourceRun:basis.source_run,sourceActive:basis.active,projectionId:r.projectionId};
    if(Object.hasOwn(r.patch,'assignee')&&r.patch.assignee!==(patches.assignee?patches.assignee.value:basis.assignee))patches.assignee={base:basis.assignee,value:r.patch.assignee,projectionId:r.projectionId};
    if(isDeepStrictEqual(patches,old?.patches??{})){await client.query('COMMIT');return {changed:false,revision:r.expectedRevision,companyRevision:revision(head.revision)};}
    const next=revision(head.revision)+1;if(!Number.isSafeInteger(next))fail('Workflow revision limit reached');
    await client.query('UPDATE defender_workflow_heads SET revision=$2 WHERE company_id=$1',[r.companyId,next]);
    // The locked customer head serializes writers. Separate INSERT/UPDATE avoids
    // running the initial-revision INSERT trigger on an existing edit.
    const {rows:[saved]}=await client.query(old?`UPDATE defender_workflow_edits SET device_id=$3,cve=$4,
      revision=$5,company_revision=$6,patches=$7::jsonb,actor=$8,reason=$9 WHERE company_id=$1 AND finding_id=$2 RETURNING *`:
      `INSERT INTO defender_workflow_edits(company_id,finding_id,device_id,cve,revision,company_revision,patches,actor,reason)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) RETURNING *`,
      [r.companyId,r.findingId,basis.device_id,basis.cve,r.expectedRevision+1,next,JSON.stringify(patches),r.actor,r.reason]);
    await beforeCommit?.();await client.query('COMMIT');return {changed:true,revision:revision(saved.revision),companyRevision:next};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
export async function readDefenderWorkflow(client,companyId){
  if(!company(companyId))fail('Explicit workflow customer required',400);await privateShadowDatabase(client,'target');
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='5s'");
    const head=(await client.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1',[companyId])).rows[0];
    const size=(await client.query('SELECT count(*)::int n,coalesce(sum(octet_length(patches::text)),0)::text bytes FROM defender_workflow_edits WHERE company_id=$1',[companyId])).rows[0];
    if(size.n>500000||Number(size.bytes)>32*1024*1024)fail('Workflow snapshot exceeds offline bounds',413);
    const {rows}=await client.query('SELECT finding_id,device_id,cve,revision,patches FROM defender_workflow_edits WHERE company_id=$1 ORDER BY finding_id',[companyId]);
    await client.query('COMMIT');return {companyId,revision:revision(head?.revision??0),rows};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
export async function defenderWorkflowUnchanged(client,snapshot){
  if(!company(snapshot?.companyId)||!Number.isSafeInteger(snapshot.revision))fail('Invalid workflow snapshot',400);
  await privateShadowDatabase(client,'target');
  const row=(await client.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1',[snapshot.companyId])).rows[0];
  return revision(row?.revision??0)===snapshot.revision;
}
