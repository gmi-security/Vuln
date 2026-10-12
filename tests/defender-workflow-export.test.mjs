import test from 'node:test';
import assert from 'node:assert/strict';
import {planDefenderWorkflowExport,applyDefenderWorkflowExport} from '../lib/db/defender-workflow-export.mjs';
const id='12345678-1234-1234-1234-123456789abc';
function fixture(){
  const company={id:'CO-TEST',name:'Fixture'},f={id:'f1',companyId:company.id,cve:'CVE-2026-1234',status:'Open',assignee:null,resolvedAt:null,score:9,defender:{deviceId:'d1',runId:'r1',active:true}};
  const input={company,baseline:{runId:'r1',findings:[f],assets:[],controls:[]},records:[structuredClone(f)],projectionId:id,sourceRun:'r1',
    workflow:{companyId:company.id,revision:1,rows:[{finding_id:'f1',device_id:'d1',cve:f.cve,patches:{status:{base:'Open',baseResolvedAt:null,value:'Resolved',resolvedAt:'2026-10-10T14:00:00Z',sourceRun:'r1'},assignee:{base:null,value:'analyst'}}}]}};
  const snapshot={companies:[[company.id,company]],findings:[[f.id,f],['other',{id:'other',companyId:'CO-OTHER',status:'Open'}]],assets:[],compensatingControls:[],meta:{defenderGenerations:{'CO-TEST':'r1'}},settings:{fixture:true},scans:[['scan',{id:'scan',status:'Completed'}]]};
  return {input,snapshot};
}
test('reverse artifact restores only workflow and preserves original timestamp, other customers and metadata without mutation',()=>{
  const {input,snapshot}=fixture(),before=structuredClone(snapshot),artifact=planDefenderWorkflowExport(input);
  const output=applyDefenderWorkflowExport(snapshot,JSON.parse(JSON.stringify(artifact)));
  assert.deepEqual(snapshot,before);assert.equal(artifact.changes.length,1);assert.equal(artifact.activationAllowed,false);
  assert.deepEqual(output.findings[0][1],{...before.findings[0][1],status:'Resolved',assignee:'analyst',resolvedAt:'2026-10-10T14:00:00Z'});
  assert.deepEqual(output.findings[1],before.findings[1]);assert.deepEqual(output.settings,before.settings);assert.deepEqual(output.scans,before.scans);
  assert.throws(()=>applyDefenderWorkflowExport(output,artifact),/baseline changed/,'replay cannot silently overwrite later workflow');
});
test('changed source, evidence, findings or workflow conflicts refuse an artifact',()=>{
  for(const mutate of [i=>i.baseline.runId='new',i=>i.records[0].score=10,i=>i.records[0].defender.deviceId='other',i=>i.records=[],
    i=>i.records.push(structuredClone(i.records[0])),i=>i.workflow.companyId='CO-OTHER',i=>i.records[0].assignee='concurrent']){
    const {input}=fixture();mutate(input);assert.throws(()=>planDefenderWorkflowExport(input));
  }
});
test('tampering, stale baseline, missing records and duplicate snapshot identity refuse application',()=>{
  const {input,snapshot}=fixture(),artifact=planDefenderWorkflowExport(input);
  const changed=structuredClone(artifact);changed.changes[0].value.assignee='tampered';assert.throws(()=>applyDefenderWorkflowExport(snapshot,changed),/altered/);
  for(const mutate of [s=>s.findings[0][1].status='Risk Accepted',s=>s.meta.defenderGenerations['CO-TEST']='new',s=>s.findings.shift(),s=>s.findings.push(s.findings[0]),s=>s.companies[0][1].name='Changed']){
    const copy=structuredClone(snapshot);mutate(copy);assert.throws(()=>applyDefenderWorkflowExport(copy,artifact));
  }
});
