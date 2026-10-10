// Offline evidence only. This module never writes legacy data or completes a
// handoff. Cross-database verification is a point-in-time observation.
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase} from './defender-platform-shadow.mjs';
import {readWriterOwnership} from './defender-writer-ownership.mjs';
import {collectDefenderWorkflowExport,applyDefenderWorkflowExport} from './defender-workflow-export.mjs';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const uuid=v=>typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v);
const collections={findings:64,assets:16,scans:8,companies:1,folders:1};
const keys=['meta',...Object.entries(collections).flatMap(([name,n])=>Array.from({length:n},(_,i)=>`${name}:${String(i).padStart(2,'0')}`))].sort();
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
// These top-level arrays represent Maps. Nested arrays retain their ordering.
export function reverseSnapshotDigest(snapshot){
  const hash=createHash('sha256'),add=v=>hash.update(JSON.stringify(canonical(v))+'\n');
  requireValue(snapshot&&typeof snapshot==='object'&&!Array.isArray(snapshot),'Complete snapshot required');
  for(const key of Object.keys(snapshot).sort()){
    add(key);const value=snapshot[key];
    if([...Object.keys(collections),'compensatingControls','identityAliases'].includes(key)){
      requireValue(Array.isArray(value),'Snapshot Map required');const seen=new Set();add(value.length);
      for(const row of [...value].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0)){
        requireValue(Array.isArray(row)&&row.length===2&&typeof row[0]==='string'&&!seen.has(row[0]),'Invalid snapshot Map identity');seen.add(row[0]);add(row);
      }
    }else add(value);
  }
  return hash.digest('hex');
}
export function reverseReceiptRequest(r){
  requireValue(r&&Object.keys(r).every(k=>['companyId','attemptId','expectedRevision','actor','reason'].includes(k))&&
    /^CO-[A-Za-z0-9-]{1,98}$/.test(r.companyId??'')&&uuid(r.attemptId)&&Number.isSafeInteger(r.expectedRevision)&&r.expectedRevision>=0&&
    typeof r.actor==='string'&&r.actor.trim()&&r.actor.length<=120&&typeof r.reason==='string'&&r.reason.trim()&&r.reason.length<=500,
  'Explicit reverse attempt, revision and audit context required; no declared evidence');return r;
}
function binding(state,r){
  const attempt=state?.data?.attempt,selected=state?.data?.lastCompleted;
  requireValue(state?.phase==='reversing'&&Number(state.revision)===r.expectedRevision&&attempt?.id===r.attemptId&&attempt.origin==='sql', 'Reverse ownership attempt changed');
  requireValue(uuid(selected?.projectionId),'Ownership-selected generation required');
  requireValue(attempt.processes?.length>0&&attempt.processes.every(id=>attempt.acks[id]),'All reverse writers must acknowledge drain');
  return {projectionId:selected.projectionId,epoch:Number(state.epoch),revision:Number(state.revision),acks:attempt.processes.map(id=>attempt.acks[id].baselineDigest)};
}
async function legacyFence(client,companyId){
  const identity=(await client.query('SELECT oid::text id,datname name FROM pg_database WHERE datname=current_database()')).rows[0];
  const stamp=(await client.query(`SELECT c.current_run::text run,c.revision,c.xmin::text connection_version,r.xmin::text run_version,r.status,r.revision source_revision
    FROM defender_connections c JOIN defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id WHERE c.company_id=$1`,[companyId])).rows[0];
  const buckets=(await client.query('SELECT key,xmin::text version,tableoid::text relation FROM vuln_store ORDER BY key')).rows;
  return {identity,stamp,buckets};
}
async function unchanged(client,companyId,expected){
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s'");const current=await legacyFence(client,companyId);await client.query('COMMIT');
    requireValue(isDeepStrictEqual(current,expected),'Legacy data or source changed during reverse verification');
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
// Explicit v1 legacy layout, read in one snapshot. Unknown/missing buckets and
// metadata overrides fail rather than silently ignoring persisted information.
async function readLegacy(client,companyId){
  await privateShadowDatabase(client,'source');const start=Date.now();await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
    await client.query("SET LOCAL statement_timeout='15s';SET LOCAL idle_in_transaction_session_timeout='60s'");
    const sizes=(await client.query('SELECT key,octet_length(data::text)::bigint bytes FROM vuln_store ORDER BY key')).rows;
    requireValue(isDeepStrictEqual(sizes.map(r=>r.key),keys)&&sizes.every(r=>Number(r.bytes)<=32*1024*1024)&&sizes.reduce((n,r)=>n+Number(r.bytes),0)<=1024*1024*1024,'Unsupported or oversized legacy snapshot');
    const fence=await legacyFence(client,companyId),{identity,stamp}=fence;
    requireValue(stamp?.status==='succeeded'&&stamp.revision===stamp.source_revision,'Complete reverse source required');
    const meta=(await client.query("SELECT data FROM vuln_store WHERE key='meta'")).rows[0].data;
    requireValue(meta&&typeof meta==='object'&&!Array.isArray(meta)&&Object.keys(collections).every(k=>!Object.hasOwn(meta,k)),'Unsupported legacy metadata overrides');
    const snapshot={...meta};for(const name of Object.keys(collections))snapshot[name]=[];
    for(const key of keys.filter(k=>k!=='meta')){
      requireValue(Date.now()-start<180000,'Reverse receipt read deadline exceeded');
      const data=(await client.query('SELECT data FROM vuln_store WHERE key=$1',[key])).rows[0].data;
      requireValue(Array.isArray(data),'Invalid legacy bucket');
      for(const row of data)snapshot[key.split(':')[0]].push(row);
    }
    await client.query('COMMIT');return {snapshot,identity,stamp,fence};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
async function locked(target,r,fn){
  await privateShadowDatabase(target,'target');await target.query('BEGIN');
  try{
    await target.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const state=(await target.query('SELECT * FROM defender_writer_ownership WHERE company_id=$1 FOR SHARE',[r.companyId])).rows[0],b=binding(state,r);
    const head=(await target.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1 FOR SHARE',[r.companyId])).rows[0];
    const result=await fn(b,Number(head?.revision??0));await target.query('COMMIT');return result;
  }catch(error){await target.query('ROLLBACK').catch(()=>{});throw error;}
}
async function stored(target,r){return (await target.query('SELECT * FROM defender_reverse_exports WHERE company_id=$1 AND attempt_id=$2',[r.companyId,r.attemptId])).rows[0];}
function matching(row,b,revision){
  requireValue(row&&Number(row.ownership_revision)===b.revision&&Number(row.ownership_epoch)===b.epoch&&row.projection_id===b.projectionId&&Number(row.workflow_revision)===revision,'Reverse export ownership or workflow changed');
}
export async function prepareOwnedReverseExport(source,target,raw,{afterCollect}={}){
  const r=reverseReceiptRequest(raw),b=binding(await readWriterOwnership(target,r.companyId),r);
  const existing=await stored(target,r);
  if(existing)return locked(target,r,(bound,rev)=>{matching(existing,bound,rev);return existing;});
  const artifact=await collectDefenderWorkflowExport(source,target,r.companyId,b.projectionId);
  requireValue(b.acks.every(d=>d===artifact.baselineDigest),'Reverse drain baselines differ');
  const legacy=await readLegacy(source,r.companyId),expected=applyDefenderWorkflowExport(legacy.snapshot,artifact);
  requireValue(legacy.stamp.run===artifact.sourceRun,'Reverse source generation changed');
  const baselineDigest=reverseSnapshotDigest(legacy.snapshot),expectedDigest=reverseSnapshotDigest(expected);
  await afterCollect?.();
  await unchanged(source,r.companyId,legacy.fence);
  return locked(target,r,async(bound,revision)=>{
    requireValue(isDeepStrictEqual(bound,b)&&revision===artifact.workflowRevision,'Reverse ownership or workflow changed during collection');
    await target.query(`INSERT INTO defender_reverse_exports(company_id,attempt_id,ownership_revision,ownership_epoch,projection_id,workflow_revision,artifact,baseline_digest,expected_digest,source_identity,source_stamp,actor,reason)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`,
    [r.companyId,r.attemptId,b.revision,b.epoch,b.projectionId,revision,JSON.stringify(artifact),baselineDigest,expectedDigest,JSON.stringify(legacy.identity),JSON.stringify(legacy.stamp),r.actor,r.reason]);
    const saved=await stored(target,r);matching(saved,bound,revision);
    requireValue(saved.artifact.artifactDigest===artifact.artifactDigest&&saved.baseline_digest===baselineDigest&&saved.expected_digest===expectedDigest&&isDeepStrictEqual(saved.source_stamp,legacy.stamp)&&isDeepStrictEqual(saved.source_identity,legacy.identity),'Conflicting reverse artifact already recorded');
    return saved;
  });
}
export async function verifyOwnedReverseRestore(source,target,raw,{afterRead,beforeCommit}={}){
  const r=reverseReceiptRequest(raw);
  const row=await locked(target,r,async(b,rev)=>{const record=await stored(target,r);matching(record,b,rev);return record;});
  const observed=await readLegacy(source,r.companyId),digest=reverseSnapshotDigest(observed.snapshot);
  requireValue(isDeepStrictEqual(observed.identity,row.source_identity)&&isDeepStrictEqual(observed.stamp,row.source_stamp)&&digest===row.expected_digest,'Restored legacy snapshot or source does not match the recorded export');
  await afterRead?.();
  await unchanged(source,r.companyId,observed.fence);
  return locked(target,r,async(b,rev)=>{
    matching(row,b,rev);
    await target.query(`INSERT INTO defender_reverse_receipts(company_id,attempt_id,restored_digest,artifact_digest,actor,reason)
      VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,[r.companyId,r.attemptId,digest,row.artifact.artifactDigest,r.actor,r.reason]);
    const receipt=(await target.query('SELECT * FROM defender_reverse_receipts WHERE company_id=$1 AND attempt_id=$2',[r.companyId,r.attemptId])).rows[0];
    requireValue(receipt.restored_digest===digest&&receipt.artifact_digest===row.artifact.artifactDigest,'Conflicting restore receipt');
    await beforeCommit?.();return receipt;
  });
}
