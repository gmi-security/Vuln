// node --experimental-vm-modules --test tests/external-scan-dispatcher.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';
import { resolve, dirname } from 'node:path';

const modules=new Map();
const events=[];
const claims={slot:null,flagged:false};
const fake={
  reserveExternalScanClaim:async(_db,input)=>{
    if(claims.slot)return {state:'busy'};
    claims.slot=input.dedupKey;events.push('reserved');return {state:'reserved'};
  },
  inspectExternalScanSlot:async()=>({claim_key:claims.slot}),
  recordExternalScanRemoteTask:async(_db,key,id)=>{
    assert.equal(key,claims.slot);events.push('persist:'+id);return {state:'remote-created'};
  },
  flagExternalScanReconciliation:async(_db,key)=>{
    assert.equal(key,claims.slot);claims.flagged=true;events.push('reconcile');return {state:'needs-reconciliation'};
  },
};
const root=resolve('.');
async function load(path){
  path=resolve(path);
  if(modules.has(path))return modules.get(path);
  const compiled=ts.transpileModule(await readFile(path,'utf8'),
    {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(compiled,{identifier:path});
  modules.set(path,mod);return mod;
}
const entry=await load('lib/external-scan-dispatcher.ts');
await entry.link(async(name,parent)=>{
  if(name==='./db/external-scan-claims.mjs')return new SyntheticModule(
    ['reserveExternalScanClaim','inspectExternalScanSlot'],function(){
      for(const k of ['reserveExternalScanClaim','inspectExternalScanSlot'])this.setExport(k,fake[k]);
    });
  if(name==='./db/external-scan-reconciliation.mjs')return new SyntheticModule(
    ['recordExternalScanRemoteTask','flagExternalScanReconciliation'],function(){
      for(const k of ['recordExternalScanRemoteTask','flagExternalScanReconciliation'])this.setExport(k,fake[k]);
    });
  if(name==='node:net'){
    const values=await import(name);return new SyntheticModule(Object.keys(values),function(){
      for(const [k,v] of Object.entries(values))this.setExport(k,v);
    });
  }
  if(name==='node:crypto'){
    const values=await import(name);return new SyntheticModule(Object.keys(values),function(){
      for(const [k,v] of Object.entries(values))this.setExport(k,v);
    });
  }
  if(name.startsWith('.'))return load(resolve(dirname(parent.identifier),name+'.ts'));
  throw Error('Unexpected import '+name);
});
await entry.evaluate();
const {dispatchOneAuthorizedExternalTarget}=entry.namespace;
const env={VULN_EXTERNAL_SCAN_DISPATCH_ENABLED:'true',GMI_SCAN_ADMISSION_ENABLED:'true',VULNERS_BRIDGE_SCHEDULER_ENABLED:'false'};
function sample(){
  const now=Date.now();
  const iso=m=>new Date(now+m*60_000).toISOString();
  const candidate={companyId:'CO-A',target:'example.org',nessusScanId:19,scheduledOccurrenceAt:iso(-120)};
  const proofs={
    scope:{companyId:'CO-A',enabled:true,revision:1,approvedTargets:['example.org']},
    window:{companyId:'CO-A',approved:true,startsAt:iso(-110),endsAt:iso(80)},
    sourceRun:{scanId:19,status:'completed',startedAt:iso(-100),completedAt:iso(-70),reportId:'run-19',coveredTargets:['example.org']},
    capacity:{checkedAt:iso(0),healthy:true,activeTaskCount:0,queuedTaskCount:0,requestedTaskCount:0}
  };
  return {candidate,proofs};
}
function deps(overrides={}){
  const s=sample();
  return {candidate:s.candidate, db:{connect(){},query(){}},
    readProofs:async()=>({...s.proofs,capacity:{...s.proofs.capacity,checkedAt:new Date().toISOString()}}),
    createTask:async(_c,_n,verify)=>{await verify();events.push('created');return 'greenbone-task-1';},
    startTask:async(_c,_id,verify)=>{await verify();events.push('started');},
    ...overrides};
}
function clear(){claims.slot=null;claims.flagged=false;events.length=0;}
test('disabled flags cause no proof reads, database reservation or requests',async()=>{
  clear();
  let reads=0;
  const d=deps({readProofs:async()=>{reads++;throw Error('never');}});
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,{...env,GMI_SCAN_ADMISSION_ENABLED:'false'});
  assert.equal(result.state,'disabled');assert.equal(reads,0);assert.deepEqual(events,[]);
});
test('complete approved path saves Greenbone ID before start and holds slot',async()=>{
  clear();
  const d=deps();
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'started');
  assert.deepEqual(events,['reserved','created','persist:greenbone-task-1','started']);
  assert.equal(claims.slot,result.claimKey);
});
test('occupied global slot blocks second launch',async()=>{
  clear();const d=deps();
  assert.equal((await dispatchOneAuthorizedExternalTarget(d.candidate,d,env)).state,'started');
  events.length=0;
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'busy');assert.equal(events.length,0);
});
test('unapproved target cannot reserve or reach Greenbone',async()=>{
  clear();const s=sample();
  const d=deps({candidate:{...s.candidate,target:'foreign.example'}});
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'hold');assert.deepEqual(events,[]);
});
test('create timeout marks hold and never starts or retries',async()=>{
  clear();const d=deps({createTask:async()=>{events.push('create-timeout');throw Error('timeout');}});
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'reconciliation-required');assert.equal(result.stage,'create');
  assert.equal(claims.flagged,true);
  assert.deepEqual(events,['reserved','create-timeout','reconcile']);
});
test('start timeout retains previously persisted Greenbone task identity',async()=>{
  clear();const d=deps({startTask:async()=>{events.push('start-timeout');throw Error('timeout');}});
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'reconciliation-required');assert.equal(result.taskId,'greenbone-task-1');
  assert.deepEqual(events,['reserved','created','persist:greenbone-task-1','start-timeout','reconcile']);
});
test('changed approval after reservation refuses create and requires reconciliation',async()=>{
  clear();const s=sample();let loads=0;
  const d=deps({readProofs:async()=>{loads++;return {
    ...s.proofs,scope:{...s.proofs.scope,revision:loads===1?1:2},
    capacity:{...s.proofs.capacity,checkedAt:new Date().toISOString()}};}});
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,env);
  assert.equal(result.state,'reconciliation-required');
  assert.deepEqual(events,['reserved','reconcile']);
});
test('legacy inventory-wide bridge scheduler and controlled dispatcher cannot coexist',async()=>{
  clear();const d=deps();
  const result=await dispatchOneAuthorizedExternalTarget(d.candidate,d,{...env,VULNERS_BRIDGE_SCHEDULER_ENABLED:'true'});
  assert.equal(result.state,'disabled');assert.equal(events.length,0);
});
