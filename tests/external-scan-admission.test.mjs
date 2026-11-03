// node --experimental-vm-modules --test tests/external-scan-admission.test.mjs
import assert from 'node:assert/strict';
import test from 'node:test';
import ts from 'typescript';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
const source=await readFile('lib/external-scan-admission.ts','utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const exact=value=>{
  if (value.includes('/')||value.includes('*')||value.includes('://')||!value) throw Error('invalid');
  return value.toLowerCase().replace(/\.$/,'');
};
const mod=new SourceTextModule(compiled);
await mod.link(async name=>{
  const entries=name==='node:crypto'?{createHash:(await import('node:crypto')).createHash}:name==='./scanner-target-scope'?{scannerExactTargetKey:exact}:null;
  assert.ok(entries,name);
  return new SyntheticModule(Object.keys(entries),function(){for(const [k,v] of Object.entries(entries))this.setExport(k,v);});
});
await mod.evaluate();
const {evaluateExternalScanAdmission,externalScanDedupKey}=mod.namespace;
function baseline(){return {
  now:'2026-11-04T03:00:00Z',dispatchEnabled:true,scannerAdmissionEnabled:true,
  candidate:{companyId:'CO-A',target:'example.org',nessusScanId:11,scheduledOccurrenceAt:'2026-11-04T01:00:00Z'},
  sourceRun:{scanId:11,status:'completed',startedAt:'2026-11-04T01:01:00Z',completedAt:'2026-11-04T02:10:00Z',reportId:'REPORT-1',coveredTargets:['example.org']},
  scope:{companyId:'CO-A',enabled:true,revision:2,approvedTargets:['example.org']},
  window:{companyId:'CO-A',approved:true,startsAt:'2026-11-04T02:00:00Z',endsAt:'2026-11-04T04:00:00Z'},
  capacity:{checkedAt:'2026-11-04T02:59:59Z',healthy:true,activeTaskCount:0,queuedTaskCount:0,requestedTaskCount:0},
  claimExists:false,
};}
const decision=overrides=>evaluateExternalScanAdmission({...baseline(),...overrides});
test('default gates hold unless both explicit enable flags are true',()=>{
  for(const field of ['dispatchEnabled','scannerAdmissionEnabled']) assert.equal(decision({[field]:false}).state,'hold');
});
test('fully attested input is only eligible for atomic claim, never a scan launch',()=>{
  const p=decision({});assert.equal(p.state,'eligible-for-atomic-claim');assert.match(p.reason,/atomically claim/);assert.match(p.dedupKey,/^[a-f0-9]{64}$/);
});
test('same customer and normalized target share durable dedup key',()=>{
  const c=baseline().candidate;assert.equal(externalScanDedupKey(c),externalScanDedupKey({...c,target:'EXAMPLE.ORG.'}));
  assert.notEqual(externalScanDedupKey(c),externalScanDedupKey({...c,scheduledOccurrenceAt:'2026-11-05T01:00:00Z'}));
});
test('no approval, wrong company, unapproved target and CIDR all hold',()=>{
  assert.equal(decision({scope:null}).state,'hold');
  assert.equal(decision({scope:{...baseline().scope,companyId:'CO-B'}}).state,'hold');
  assert.equal(decision({candidate:{...baseline().candidate,target:'other.org'}}).state,'hold');
  assert.equal(decision({candidate:{...baseline().candidate,target:'10.0.0.0/24'}}).state,'hold');
});
test('window absent, revoked, outside time or wrong customer holds',()=>{
  assert.equal(decision({window:null}).state,'hold');
  assert.equal(decision({window:{...baseline().window,approved:false}}).state,'hold');
  assert.equal(decision({now:'2026-11-04T04:00:00Z'}).state,'hold');
  assert.equal(decision({window:{...baseline().window,companyId:'CO-B'}}).state,'hold');
});
test('missing, unrelated, incomplete and outdated Nessus evidence all hold',()=>{
  assert.equal(decision({sourceRun:null}).state,'hold');
  assert.equal(decision({sourceRun:{...baseline().sourceRun,scanId:12}}).state,'hold');
  assert.equal(decision({sourceRun:{...baseline().sourceRun,status:'running'}}).state,'hold');
  assert.equal(decision({sourceRun:{...baseline().sourceRun,coveredTargets:[]}}).state,'hold');
  assert.equal(decision({sourceRun:{...baseline().sourceRun,startedAt:'2026-11-03T01:01:00Z'}}).state,'hold');
});
test('active work, stale capacity and uncertain deduplication claim all hold',()=>{
  assert.equal(decision({capacity:{...baseline().capacity,activeTaskCount:1}}).state,'hold');
  assert.equal(decision({capacity:{...baseline().capacity,checkedAt:'2026-11-04T02:59:00Z'}}).state,'hold');
  assert.equal(decision({claimExists:null}).state,'hold');
  assert.equal(decision({claimExists:true}).state,'hold');
});

test('the existing +60-minute offset is a hard lower bound, but elapsed time alone cannot authorize',()=>{
  const input=baseline();
  input.now='2026-11-04T01:59:59Z';
  input.window={...input.window,startsAt:'2026-11-04T01:30:00Z'};
  input.sourceRun={...input.sourceRun,completedAt:'2026-11-04T01:50:00Z'};
  input.capacity={...input.capacity,checkedAt:'2026-11-04T01:59:58Z'};
  assert.match(evaluateExternalScanAdmission(input).reason,/60-minute offset/);
  input.now='2026-11-04T02:00:01Z';
  input.capacity={...input.capacity,checkedAt:'2026-11-04T02:00:00Z'};
  assert.equal(evaluateExternalScanAdmission(input).state,'eligible-for-atomic-claim');
  input.sourceRun={...input.sourceRun,status:'running'};
  assert.equal(evaluateExternalScanAdmission(input).state,'hold');
});
test('a Nessus job completing later than +60 minutes still blocks until it actually finishes',()=>{
  const input=baseline();
  input.now='2026-11-04T02:01:00Z';
  input.capacity={...input.capacity,checkedAt:'2026-11-04T02:00:59Z'};
  assert.equal(evaluateExternalScanAdmission(input).state,'hold');
  assert.match(evaluateExternalScanAdmission(input).reason,/Nessus run timing/);
});
