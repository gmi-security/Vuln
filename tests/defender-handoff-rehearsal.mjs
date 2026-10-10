// Test-only protocol rehearsal. No application imports this file. The gate is
// not installed around live writers and cannot grant production ownership.
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {privateShadowDatabase} from '../lib/db/defender-platform-shadow.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
const requireValue=(ok,message)=>{if(!ok)throw Error(message);};
const json=value=>JSON.parse(JSON.stringify(value));
export function createRehearsalGate(){
  let held=null,active=0,epoch=0;
  return {
    async run(fn){requireValue(!held,'Writer admission is paused');active++;epoch++;
      try{return await fn();}finally{active--;epoch++;}},
    hold(){requireValue(!held&&!active,'Writers must finish before handoff');const owner=Symbol('rehearsal'),captured=epoch;held=owner;
      return {valid:()=>held===owner&&epoch===captured&&active===0,release(){if(held===owner)held=null;}};},
  };
}
function comparable(input){
  const id=input.company?.id;requireValue(/^CO-[A-Za-z0-9-]+$/.test(id??''),'Explicit known customer required');
  const ordered=(rows,max)=>{
    requireValue(Array.isArray(rows)&&rows.length<=max,'Invalid handoff collection');
    const ids=new Set();for(const row of rows){requireValue(row.companyId===id&&typeof row.id==='string'&&!ids.has(row.id),'Invalid handoff identity');ids.add(row.id);}
    return [...rows].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
  };
  return json({company:input.company,runId:input.baseline.runId??null,
    findings:ordered(input.baseline.findings,500000),assets:ordered(input.baseline.assets,100000),controls:ordered(input.controls,100000)});
}
export function captureLegacyCustomer(s,companyId){
  requireValue(s.companies.has(companyId),'Customer missing from memory');
  return comparable({company:s.companies.get(companyId),baseline:{runId:s.meta.defenderGenerations?.[companyId]??null,
    findings:[...s.findings.values()].filter(f=>f.companyId===companyId),assets:[...s.assets.values()].filter(a=>a.companyId===companyId)},
    controls:[...s.compensatingControls.values()].filter(c=>c.companyId===companyId)});
}
export async function rehearseDefenderHandoff({source,target,companyId,gate,captureMemory,flush,prepare,capture,afterCollect,afterPlan,afterBatch}){
  // Do this before invoking any supplied writer, even a flush callback.
  await privateShadowDatabase(source,'source');await privateShadowDatabase(target,'target');
  let lease,stage='pause',built;
  try{
    lease=gate.hold();const before=captureMemory();
    requireValue(before.company.id===companyId,'Memory customer mismatch');
    const unchanged=()=>requireValue(lease.valid()&&isDeepStrictEqual(before,captureMemory()),'Memory changed during handoff');
    stage='flush';await flush({throwOnError:true});unchanged();
    stage='verify-and-build';
    built=await buildDefenderRefresh(source,target,companyId,{prepare,capture,
      afterCollect:async input=>{requireValue(isDeepStrictEqual(before,comparable(input)),'Saved customer state differs from memory');await afterCollect?.();unchanged();},
      afterPlan:async()=>{await afterPlan?.();unchanged();},
      afterBatch:async event=>{await afterBatch?.(event);unchanged();},
    });
    unchanged();requireValue(built.state==='comparison-only','Saved source or baseline changed during handoff');
    return {state:'rehearsed',handoffAllowed:false,publicationAllowed:false,projectionId:built.projectionId,
      capturedFindings:before.findings.length,memoryDigest:createHash('sha256').update(JSON.stringify(before)).digest('hex')};
  }catch(error){return {state:'refused',stage,reason:error.message,handoffAllowed:false,publicationAllowed:false,...(built?{projectionId:built.projectionId}:{})};}
  finally{lease?.release();}
}
