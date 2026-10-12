import test from 'node:test';
import assert from 'node:assert/strict';
import {handoffBaselineDigest} from '../lib/db/defender-handoff-evidence.mjs';
import {completeVerifiedOwnership} from '../lib/db/defender-writer-ownership.mjs';
import {editOwnedDefenderWorkflow} from '../lib/db/defender-workflow-edits.mjs';
const fixture=()=>({company:{id:'CO-TEST',name:'fixture'},runId:'run',findings:[{id:'b',status:'Open',extra:{z:1,a:2}},{id:'a',status:'Resolved'}],assets:[],controls:[]});
test('handoff evidence is stable across JSONB key/bucket order and changes with workflow/source/customer input',()=>{
  const value=fixture(),hash=handoffBaselineDigest(value);
  const reordered={...value,company:{name:'fixture',id:'CO-TEST'},findings:[value.findings[1],{extra:{a:2,z:1},status:'Open',id:'b'}]};
  assert.equal(handoffBaselineDigest(reordered),hash);
  for(const update of [v=>v.findings[0].status='Resolved',v=>v.runId='new-run',v=>v.company.id='CO-OTHER',v=>v.assets.push({id:'asset'}),v=>v.controls.push({id:'control'})]){
    const changed=fixture();update(changed);assert.notEqual(handoffBaselineDigest(changed),hash);
  }
});
test('declared completion evidence and wrong-customer owned edits fail before database access',async()=>{
  const noDb={query(){throw Error('database should not be accessed');}},id='12345678-1234-1234-1234-123456789abc';
  await assert.rejects(()=>completeVerifiedOwnership(noDb,noDb,{projectionId:id,attemptId:id,candidateDigest:'a'.repeat(64)}),/not declared/);
  const edit={companyId:'CO-TEST',findingId:'f1',projectionId:id,expectedRevision:0,patch:{assignee:'fixture'},actor:'fixture',reason:'review'};
  await assert.rejects(()=>editOwnedDefenderWorkflow(noDb,edit,{companyId:'CO-OTHER',owner:'sql'}),/Matching SQL/);
  await assert.rejects(()=>editOwnedDefenderWorkflow(noDb,edit,{companyId:'CO-TEST',owner:'legacy'}),/Matching SQL/);
});
