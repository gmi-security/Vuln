import test from 'node:test';
import assert from 'node:assert/strict';
import {refreshModules,company,when,snapshot,storeFixture,inputFrom} from './defender-refresh-fixture.mjs';
const {store,candidate:{prepareDefenderRefreshCandidate:prepare}}=await refreshModules();
function compare(input){
  const s=storeFixture();s.findings=new Map(input.baseline.findings.map(f=>[f.id,structuredClone(f)]));s.assets=new Map(input.baseline.assets.map(a=>[a.id,structuredClone(a)]));
  s.meta.defenderGenerations[company.id]=input.baseline.runId;globalThis.__vulnStore=s;
  const before=structuredClone(input),value=prepare(input,(f,inventory)=>store.riskFields(s,{...f,inventory}));
  assert.deepEqual(input,before);store.publishDefenderSnapshot(input.source.snapshot);
  assert.deepEqual(value.records,[...s.findings.values()].filter(f=>f.defender));assert.deepEqual(value.assets,[...s.assets.values()]);
  return value;
}
function baseline(){const s=storeFixture();globalThis.__vulnStore=s;store.publishDefenderSnapshot(snapshot({runId:'old-run',observedAt:'2026-10-08T12:00:00Z'}));return s;}
test('new, changed and correlated candidates exactly match the existing publication without mutating input',()=>{
  compare(inputFrom(storeFixture()));const s=baseline(),f=[...s.findings.values()][0];f.status='Risk Accepted';f.assignee='analyst';
  const result=compare(inputFrom(s));assert.equal(result.records[0].status,'Risk Accepted');assert.equal(result.records[0].assignee,'analyst');assert.equal(result.records[0].id,f.id);
  const mixed=baseline(),m=[...mixed.findings.values()][0];m.connector='nessus';m.seenBy=['nessus'];delete m.defender;m.remediation='Scanner remediation';mixed.meta.defenderGenerations={};
  const linked=compare(inputFrom(mixed));assert.equal(linked.records[0].id,m.id);assert.deepEqual(linked.records[0].seenBy,['nessus','defender']);
});
test('missing and stale devices retain history; fresh absence resolves only eligible Defender findings',()=>{
  for(const devices of [[],[{...snapshot().devices[0],lastSeen:'2026-10-01T00:00:00Z'}]]){
    const s=baseline();const r=compare(inputFrom(s,snapshot({devices,findings:[]})));assert.equal(r.records[0].status,'Open');assert.equal(r.records[0].defender.runId,'old-run');
  }
  const s=baseline(),f=[...s.findings.values()][0];f.status='In Remediation';f.assignee='analyst';
  const closed=compare(inputFrom(s,snapshot({findings:[]})));assert.equal(closed.records[0].status,'Resolved');assert.equal(closed.records[0].assignee,'analyst');
  for(const status of ['Risk Accepted','False Positive']){const s=baseline();[...s.findings.values()][0].status=status;assert.equal(compare(inputFrom(s,snapshot({findings:[]}))).records[0].status,status);}
  const mixed=baseline(),m=[...mixed.findings.values()][0];m.seenBy=['nessus','defender'];m.connector='nessus';
  assert.equal(compare(inputFrom(mixed,snapshot({findings:[]}))).records[0].status,'Open');
});
test('same-run retries preserve later manual resolution without rescoring; a new detection follows legacy reopening',()=>{
  const s=baseline(),f=[...s.findings.values()][0];f.status='Resolved';f.resolvedAt=when;
  const input=inputFrom(s,snapshot({runId:'old-run'}));const same=prepare(input,()=>{throw Error('Must not rescore an already-applied run');});
  assert.equal(same.sameRun,true);assert.deepEqual(same.records,input.baseline.findings);compare(input);
  assert.equal(compare(inputFrom(s)).records[0].status,'Open');
});
test('invalid scope, older observations and duplicate identities are refused before scoring',()=>{
  for(const mutate of [i=>i.company.id='CO-WRONG',i=>i.company.isDemo=true,i=>i.assessmentContext='',i=>i.source.revision=0,
    i=>i.baseline.findings[0].companyId='CO-OTHER',i=>i.baseline.findings.push(i.baseline.findings[0]),
    i=>i.source.snapshot.devices.push(i.source.snapshot.devices[0]),i=>i.source.snapshot.findings.push(i.source.snapshot.findings[0]),
    i=>i.source.snapshot.observedAt='2026-10-01T00:00:00Z']){
    const i=structuredClone(inputFrom(baseline()));mutate(i);assert.throws(()=>prepare(i,()=>{throw Error('unexpected scoring');}),e=>!e.message.includes('unexpected scoring'));
  }
});
