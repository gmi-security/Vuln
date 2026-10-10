// Offline workflow-only reverse artifact. No publication, legacy database write
// or ownership transition is performed by this module.
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {handoffBaselineDigest} from './defender-handoff-evidence.mjs';
import {applyDefenderWorkflow} from './defender-workflow-overlay.mjs';
import {privateShadowDatabase,reconstructShadowSql} from './defender-platform-shadow.mjs';
import {readDefenderRefreshBaseline,checkDefenderRefreshBaseline} from './defender-refresh-baseline.mjs';
import {readDefenderWorkflow,defenderWorkflowUnchanged} from './defender-workflow-edits.mjs';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const json=value=>JSON.parse(JSON.stringify(value));
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
const hash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const fields=f=>({status:f.status,assignee:f.assignee,resolvedAt:f.resolvedAt});
const withoutWorkflow=f=>{const {status,assignee,resolvedAt,...rest}=f;return rest;};
function indexed(rows){const result=new Map();for(const row of rows){requireValue(typeof row.id==='string'&&!result.has(row.id),'Duplicate or missing export identity');result.set(row.id,row);}return result;}
export function planDefenderWorkflowExport({company,baseline,records,workflow,projectionId,sourceRun,baselineFence}){
  requireValue(uuid(projectionId)&&company?.id===workflow.companyId&&baseline.runId===sourceRun,'Matching customer and applied source generation required');
  const old=indexed(baseline.findings.filter(f=>f.defender)),next=indexed(records);
  requireValue(old.size===next.size&&[...old.keys()].every(id=>next.has(id)),'Export cannot add or remove findings');
  for(const [id,f] of next){requireValue(f.companyId===company.id&&isDeepStrictEqual(withoutWorkflow(f),withoutWorkflow(old.get(id))),'Non-workflow finding evidence changed');}
  const applied=applyDefenderWorkflow({companyId:company.id,records},workflow);
  requireValue(applied.state==='applied','Workflow conflicts with the selected generation');
  const changes=[];
  for(const f of applied.candidate.records){const before=old.get(f.id);if(!isDeepStrictEqual(fields(before),fields(f)))changes.push({findingId:f.id,deviceId:f.defender.deviceId,cve:f.cve,base:fields(before),value:fields(f)});}
  changes.sort((a,b)=>a.findingId<b.findingId?-1:a.findingId>b.findingId?1:0);
  const artifact={version:1,kind:'defender-workflow-only',companyId:company.id,projectionId,sourceRun,workflowRevision:workflow.revision,
    baselineDigest:handoffBaselineDigest({company,...baseline}),changes,activationAllowed:false,...(baselineFence?{baselineFence}:{})};
  requireValue(Buffer.byteLength(JSON.stringify(artifact))<=32*1024*1024,'Reverse artifact exceeds 32 MiB');
  return {...artifact,artifactDigest:hash(artifact)};
}
function snapshotScope(snapshot,companyId){
  for(const key of ['companies','findings','assets','compensatingControls'])requireValue(Array.isArray(snapshot?.[key]),'Complete legacy snapshot collections required');
  const rows=key=>snapshot[key].map(entry=>{requireValue(Array.isArray(entry)&&entry.length===2&&entry[0]===entry[1]?.id,'Invalid legacy snapshot entry');return entry[1];});
  const companies=rows('companies'),findings=rows('findings'),assets=rows('assets'),controls=rows('compensatingControls');
  for(const collection of [companies,findings,assets,controls])indexed(collection);
  const company=companies.find(c=>c.id===companyId);requireValue(company,'Export customer is absent');
  return {company,runId:snapshot.meta?.defenderGenerations?.[companyId]??null,findings:findings.filter(f=>f.companyId===companyId),
    assets:assets.filter(a=>a.companyId===companyId),controls:controls.filter(c=>c.companyId===companyId)};
}
export function applyDefenderWorkflowExport(snapshot,artifact){
  const {artifactDigest,...content}=artifact??{};
  requireValue(content.version===1&&content.kind==='defender-workflow-only'&&content.activationAllowed===false&&uuid(content.projectionId)&&Array.isArray(content.changes)&&hash(content)===artifactDigest,'Invalid or altered reverse artifact');
  requireValue(Buffer.byteLength(JSON.stringify(artifact))<=32*1024*1024,'Reverse artifact exceeds 32 MiB');
  const scope=snapshotScope(snapshot,content.companyId);
  requireValue(scope.runId===content.sourceRun&&handoffBaselineDigest(scope)===content.baselineDigest,'Legacy baseline changed; reverse export refused');
  const result=json(snapshot),findings=new Map(result.findings),seen=new Set();
  for(const change of content.changes){
    const f=findings.get(change.findingId);requireValue(!seen.has(change.findingId),'Duplicate reverse finding');
    Object.assign(f,applyDefenderWorkflowChange(f,change,content.companyId));seen.add(f.id);
  }
  return result;
}
export function applyDefenderWorkflowChange(f,change,companyId){
  const v=change.value;
  requireValue(f?.id===change.findingId&&f.companyId===companyId&&f.defender?.deviceId===change.deviceId&&f.cve===change.cve&&isDeepStrictEqual(fields(f),change.base),'Reverse finding identity or workflow changed');
  requireValue(v&&['Open','In Remediation','Risk Accepted','False Positive','Resolved'].includes(v.status)&&(v.assignee===null||typeof v.assignee==='string')&&
    (v.resolvedAt===null||typeof v.resolvedAt==='string')&&Object.keys(v).sort().join(',')==='assignee,resolvedAt,status','Invalid reverse workflow value');
  return {...f,...v};
}
export async function collectDefenderWorkflowExport(source,target,companyId,projectionId,{afterCollect,deadlineMs=180000}={}){
  requireValue(uuid(projectionId)&&Number.isInteger(deadlineMs)&&deadlineMs>0&&deadlineMs<=300000,'Bounded explicit export required');
  await privateShadowDatabase(source,'source');await privateShadowDatabase(target,'target');
  const start=Date.now(),check=()=>requireValue(Date.now()-start<deadlineMs,'Reverse export deadline exceeded');
  const input=await readDefenderRefreshBaseline(source,companyId,{deadlineMs}),workflow=await readDefenderWorkflow(target,companyId);check();
  await target.query("SET statement_timeout='15s'");
  const g=(await target.query(`SELECT g.source_run,g.finding_count FROM defender_shadow_generations g JOIN defender_shadow_read_summary s USING(company_id,projection_id)
    WHERE g.company_id=$1 AND g.projection_id=$2 AND g.state='verified' AND g.reads_sealed AND g.model_version=2 AND s.read_version=1 AND s.finding_count=g.finding_count`,[companyId,projectionId])).rows[0];
  requireValue(g&&g.finding_count<=500000&&g.source_run===input.source.snapshot.runId&&g.source_run===input.baseline.runId,'Verified generation must match current and applied source');
  const records=[];let bytes=0;
  for(let offset=0;offset<g.finding_count;offset+=500){
    check();const query=reconstructShadowSql+' AND f.legacy_order >= $3 AND f.legacy_order < $4 ORDER BY f.legacy_order';
    const size=(await target.query(`SELECT count(*)::int n,coalesce(sum(octet_length(record::text)),0)::text bytes FROM (${query}) batch`,[companyId,projectionId,offset,offset+500])).rows[0];
    bytes+=Number(size.bytes);requireValue(size.n===Math.min(500,g.finding_count-offset)&&Number(size.bytes)<=16*1024*1024&&bytes<=512*1024*1024,'Incomplete or oversized reverse generation');
    records.push(...(await target.query(query,[companyId,projectionId,offset,offset+500])).rows.map(r=>r.record));
  }
  const artifact=planDefenderWorkflowExport({company:input.company,baseline:{...input.baseline,controls:input.controls},records,workflow,projectionId,sourceRun:g.source_run,baselineFence:input.baselineFence});
  await afterCollect?.();check();
  requireValue((await checkDefenderRefreshBaseline(source,input.baselineFence)).unchanged&&await defenderWorkflowUnchanged(target,workflow),'Source or workflow changed during reverse export');
  return artifact;
}
