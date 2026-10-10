import test from 'node:test';
import assert from 'node:assert/strict';
import {defenderWorkflowEditRequest} from '../lib/db/defender-workflow-edits.mjs';
import {applyDefenderWorkflow} from '../lib/db/defender-workflow-overlay.mjs';
const request={companyId:'CO-TEST',findingId:'f1',projectionId:'12345678-1234-1234-1234-123456789abc',expectedRevision:0,patch:{assignee:' analyst '},actor:'fixture',reason:'review'};
const finding={id:'f1',companyId:'CO-TEST',cve:'CVE-2026-1234',status:'Open',assignee:null,resolvedAt:null,defender:{deviceId:'d1',runId:'r1',active:true}};
const candidate=()=>({companyId:'CO-TEST',records:[structuredClone(finding)]});
const decision=patches=>({companyId:'CO-TEST',revision:1,rows:[{finding_id:'f1',device_id:'d1',cve:finding.cve,revision:1,patches}]});
const status=value=>({base:'Open',baseResolvedAt:null,value,resolvedAt:['Resolved','False Positive'].includes(value)?'2026-10-10T12:00:00Z':null,sourceRun:'r1'});
test('workflow edits require explicit customer, version, known fields and audit context',()=>{
  assert.equal(defenderWorkflowEditRequest(request).patch.assignee,'analyst');
  assert.equal(defenderWorkflowEditRequest({...request,patch:{assignee:' '}}).patch.assignee,null);
  for(const invalid of [null,[],{}, {...request,companyId:'all'},{...request,expectedRevision:-1},{...request,expectedRevision:'0'},
    {...request,projectionId:'current'},{...request,actor:' '},{...request,reason:''},{...request,patch:{}},{...request,patch:{cvss:10}},
    {...request,patch:{status:'closed'}},{...request,patch:{assignee:2}},{...request,unexpected:true}])assert.throws(()=>defenderWorkflowEditRequest(invalid),e=>e.status===400);
});
test('overlay preserves independent decisions and leaves source evidence and inputs unchanged',()=>{
  for(const value of ['Risk Accepted','Resolved','False Positive','In Remediation']){
    const input=candidate(),before=structuredClone(input),snapshot=decision({status:status(value),assignee:{base:null,value:'analyst'}});
    const result=applyDefenderWorkflow(input,snapshot);assert.equal(result.state,'applied');assert.deepEqual(input,before);
    assert.equal(result.candidate.records[0].status,value);assert.equal(result.candidate.records[0].assignee,'analyst');
    assert.deepEqual(result.candidate.records[0].defender,before.records[0].defender);assert.equal(result.candidate.workflowRevision,1);
    assert.equal(result.candidate.workflowDigest.length,64);
    assert.deepEqual(applyDefenderWorkflow(result.candidate,snapshot).candidate,result.candidate);
  }
  const input=candidate();input.records[0].status='Resolved';input.records[0].resolvedAt='2026-10-10T11:00:00Z';
  assert.equal(applyDefenderWorkflow(input,decision({assignee:{base:null,value:'analyst'}})).candidate.records[0].status,'Resolved');
});
test('new active imports conflict with resolution while risk acceptance can survive a refresh',()=>{
  const input=candidate();input.records[0].defender.runId='r2';
  const result=applyDefenderWorkflow(input,decision({status:status('Resolved')}));
  assert.equal(result.state,'conflict');assert.equal(result.candidate,undefined);assert.match(result.conflicts[0].reason,/newer source import/);
  assert.equal(applyDefenderWorkflow(input,decision({status:status('Risk Accepted')})).state,'applied');
  input.records[0].status='Resolved';input.records[0].resolvedAt='source-time';input.records[0].defender.active=false;
  assert.equal(applyDefenderWorkflow(input,decision({status:status('Risk Accepted')})).state,'conflict');
});
test('changed assignment, status, identity or missing findings fail closed without partial output',()=>{
  for(const change of [{assignee:'other'},{status:'In Remediation'},{cve:'CVE-2026-9999'},{companyId:'CO-OTHER'},{defender:{deviceId:'d2'}}]){
    const input=candidate();Object.assign(input.records[0],change);
    const result=applyDefenderWorkflow(input,decision({status:status('Resolved'),assignee:{base:null,value:'analyst'}}));
    assert.equal(result.state,'conflict');assert.equal(result.candidate,undefined);
  }
  const snapshot=decision({status:status('Resolved')});
  assert.equal(applyDefenderWorkflow({...candidate(),records:[]},snapshot).state,'conflict');
  assert.throws(()=>applyDefenderWorkflow(candidate(),{...snapshot,companyId:'CO-OTHER'}),/customer/);
  assert.throws(()=>applyDefenderWorkflow(candidate(),{...snapshot,rows:[...snapshot.rows,...snapshot.rows]}),/Duplicate/);
  const many={...snapshot,rows:Array.from({length:150},(_,i)=>({...snapshot.rows[0],finding_id:`missing-${i}`}))};
  const result=applyDefenderWorkflow(candidate(),many);assert.equal(result.conflictCount,150);assert.equal(result.conflicts.length,100);
});
