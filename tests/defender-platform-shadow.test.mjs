import test from 'node:test';
import assert from 'node:assert/strict';
import {projectDefenderFinding} from '../lib/db/defender-platform-shadow.mjs';
export const fixture=(extra={})=>({id:'F-1',companyId:'CO-A',cve:'CVE-2026-1234',asset:'legacy-asset',connector:'defender',
  status:'Risk Accepted',assignee:'operator',firstSeen:'2026-01-01T00:00:00Z',lastSeen:'2026-09-01T00:00:00Z',resolvedAt:null,
  severity:'High',cvss:8.1,realRisk:42,riskPriority:'Medium',description:'Preserve details',seenBy:['defender','nessus'],
  defender:{deviceId:'d',runId:'older',observedAt:'2026-09-01T00:00:00Z',active:true,cvss:null,remediation:'Recommended fix',otherRemediation:'Other evidence'},...extra});
test('preserves workflow, assessment, unknown source score, old evidence and extension fields without mutation',()=>{
  const input=fixture({futureField:{value:1}}),before=structuredClone(input),p=projectDefenderFinding(input,'CO-A');
  assert.deepEqual(input,before);assert.equal(p.id,input.id);assert.equal(p.status,'Risk Accepted');
  assert.equal(p.sourceCvss,null);assert.equal(p.cvss,8.1);assert.equal(p.realRisk,42);assert.equal(p.runId,'older');
  assert.deepEqual(p.detail.futureField,{value:1});assert.equal(p.sourceDetail.otherRemediation,'Other evidence');
  assert.equal(p.detail.defender,undefined);assert.equal(p.detail.status,undefined);
});
test('resolved and inactive evidence stays resolved and inactive',()=>{
  const f=fixture({status:'Resolved',resolvedAt:'2026-10-01'});f.defender.active=false;
  const p=projectDefenderFinding(f,'CO-A');assert.equal(p.active,false);assert.equal(p.status,'Resolved');assert.equal(p.resolvedAt,'2026-10-01');
});
test('rejects other customers, missing evidence, invented workflow and invalid scores',()=>{
  for(const [f,company] of [[fixture(),'CO-B'],[fixture({defender:undefined}),'CO-A'],[fixture({status:'Done'}),'CO-A'],
    [fixture({cvss:NaN}),'CO-A'],[fixture({realRisk:101}),'CO-A'],[fixture({assignee:undefined}),'CO-A']])
    assert.throws(()=>projectDefenderFinding(f,company));
});
