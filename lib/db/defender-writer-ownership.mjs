// Offline ownership protocol. No live route/writer calls this module. Recording
// phase=sql never selects a publication or grants production write permission.
import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase} from './defender-platform-shadow.mjs';
export const defenderWriterKinds=Object.freeze(['admin-reset','assessment','company-lifecycle','defender-publication','manual-edit','persistence','scan-lifecycle','scanner-import','startup']);
const fail=message=>{throw Object.assign(Error(message),{status:409});};
const requireValue=(ok,message)=>{if(!ok)fail(message);};
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const number=value=>Number.isSafeInteger(value)&&value>=0&&value<Number.MAX_SAFE_INTEGER;
function scope(companyId){requireValue(typeof companyId==='string'&&/^CO-[A-Za-z0-9-]{1,98}$/.test(companyId),'Explicit ownership customer required');}
function audit(r){requireValue(typeof r.actor==='string'&&r.actor.trim()&&r.actor.length<=120&&typeof r.reason==='string'&&r.reason.trim()&&r.reason.length<=500,'Ownership audit context required');}
const unpack=row=>row?{...row,revision:Number(row.revision),epoch:Number(row.epoch)}:null;
export function ownershipTransition(state,r){
  requireValue(state&&number(state.revision)&&number(state.epoch),'Valid ownership state required');
  requireValue(number(r.expectedRevision)&&r.expectedRevision===state.revision,'Ownership changed; reload before transition');audit(r);
  const next=structuredClone(state),normal=['legacy','sql'].includes(state.phase);
  if(r.action==='register'){
    requireValue(normal&&r.owner===state.phase,'Writer owner is not active');
    requireValue(uuid(r.processId)&&r.inventoryVersion===1&&Array.isArray(r.writerKinds)&&isDeepStrictEqual([...r.writerKinds].sort(),defenderWriterKinds),'Complete writer inventory required');
    requireValue(!Object.hasOwn(next.data.participants,r.processId),'Process already registered');
    requireValue(Object.keys(next.data.participants).length<64,'Ownership participant limit reached');
    next.data.participants[r.processId]={owner:r.owner,inventoryVersion:1};
  }else if(r.action==='begin'){
    requireValue(normal&&uuid(r.attemptId)&&Object.keys(state.data.participants).length>0,'Registered writers and new attempt required');
    next.phase=state.phase==='legacy'?'draining':'reversing';next.epoch++;
    next.data.attempt={id:r.attemptId,origin:state.phase,processes:Object.keys(state.data.participants).sort(),acks:{}};
  }else{
    const attempt=next.data.attempt;
    requireValue(!normal&&attempt&&uuid(r.attemptId)&&r.attemptId===attempt.id,'Current ownership attempt required');
    if(r.action==='ack'){
      requireValue(attempt.processes.includes(r.processId)&&!Object.hasOwn(attempt.acks,r.processId),'Undrained registered process required');
      requireValue(r.pendingWrites===0&&r.strictFlush===true&&digest(r.baselineDigest),'Strict save and zero pending writes required');
      attempt.acks[r.processId]={baselineDigest:r.baselineDigest};
    }else if(r.action==='finish'){
      requireValue(attempt.processes.every(id=>attempt.acks[id]),'All registered processes must acknowledge drain');
      requireValue(digest(r.baselineDigest)&&attempt.processes.every(id=>attempt.acks[id].baselineDigest===r.baselineDigest),'Drained process baselines differ');
      requireValue(digest(r.candidateDigest)&&number(r.workflowRevision),'Verified candidate and workflow revision required');
      if(state.phase==='reversing')requireValue(digest(r.reverseExportDigest)&&r.reverseExportDigest===r.baselineDigest,'Verified reverse export required');
      next.phase=attempt.origin==='legacy'?'sql':'legacy';next.epoch++;
      next.data={participants:{},attempt:null,lastCompleted:{attemptId:attempt.id,baselineDigest:r.baselineDigest,candidateDigest:r.candidateDigest,workflowRevision:r.workflowRevision,
        ...(state.phase==='reversing'?{reverseExportDigest:r.reverseExportDigest}:{})}};
    }else if(r.action==='abort'){
      next.phase=attempt.origin;next.epoch++;next.data={participants:{},attempt:null};
    }else fail('Unknown ownership action');
  }
  next.revision++;next.actor=r.actor;next.reason=r.reason;
  return next;
}
export async function readWriterOwnership(client,companyId){
  scope(companyId);await privateShadowDatabase(client,'target');
  return unpack((await client.query('SELECT * FROM defender_writer_ownership WHERE company_id=$1',[companyId])).rows[0]);
}
async function transaction(client,fn){
  await privateShadowDatabase(client,'target');await client.query('BEGIN');
  try{await client.query("SET LOCAL statement_timeout='5s';SET LOCAL lock_timeout='2s';SET LOCAL idle_in_transaction_session_timeout='15s'");
    const result=await fn();await client.query('COMMIT');return result;
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}
}
export async function initializeWriterOwnership(client,{companyId,actor,reason}){
  scope(companyId);audit({actor,reason});
  return transaction(client,async()=>{
    const known=(await client.query("SELECT 1 FROM defender_shadow_generations WHERE company_id=$1 AND state='verified' LIMIT 1",[companyId])).rowCount;
    requireValue(known,'Verified customer required');
    await client.query(`INSERT INTO defender_writer_ownership(company_id,revision,epoch,phase,data,actor,reason)
      VALUES($1,0,0,'legacy','{"participants":{},"attempt":null}',$2,$3) ON CONFLICT DO NOTHING`,[companyId,actor,reason]);
    return unpack((await client.query('SELECT * FROM defender_writer_ownership WHERE company_id=$1',[companyId])).rows[0]);
  });
}
export async function transitionWriterOwnership(client,r,{beforeCommit}={}){
  scope(r.companyId);
  return transaction(client,async()=>{
    const old=unpack((await client.query('SELECT * FROM defender_writer_ownership WHERE company_id=$1 FOR UPDATE',[r.companyId])).rows[0]);
    const next=ownershipTransition(old,r);
    if(r.action==='finish'){
      // Serialize against the isolated workflow writer's own revision lock.
      await client.query('INSERT INTO defender_workflow_heads(company_id) VALUES($1) ON CONFLICT DO NOTHING',[r.companyId]);
      const head=(await client.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1 FOR UPDATE',[r.companyId])).rows[0];
      requireValue(Number(head.revision)===r.workflowRevision,'Workflow changed after handoff evidence');
    }
    const saved=unpack((await client.query(`UPDATE defender_writer_ownership SET revision=$2,epoch=$3,phase=$4,data=$5::jsonb,actor=$6,reason=$7
      WHERE company_id=$1 RETURNING *`,[r.companyId,next.revision,next.epoch,next.phase,JSON.stringify(next.data),r.actor,r.reason])).rows[0]);
    await beforeCommit?.();return saved;
  });
}
export async function withOwnershipWrite(client,token,fn){
  scope(token.companyId);requireValue(uuid(token.processId)&&number(token.epoch)&&['legacy','sql'].includes(token.owner)&&typeof fn==='function','Explicit writer token required');
  return transaction(client,async()=>{
    // Hold the shared row lock for the entire SQL write. A phase transition's
    // exclusive lock waits for this transaction; a preflight check alone is unsafe.
    const state=unpack((await client.query('SELECT * FROM defender_writer_ownership WHERE company_id=$1 FOR SHARE',[token.companyId])).rows[0]);
    requireValue(state&&state.phase===token.owner&&state.epoch===token.epoch&&state.data.participants[token.processId]?.owner===token.owner,'Writer fenced by ownership state');
    return fn(client);
  });
}
