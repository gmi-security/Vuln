import test from 'node:test';
import assert from 'node:assert/strict';
import {ownershipTransition,defenderWriterKinds} from '../lib/db/defender-writer-ownership.mjs';
const processId='12345678-1234-1234-1234-123456789abc',attemptId='abcdef12-1234-1234-1234-123456789abc';
const hash='a'.repeat(64),base=()=>({revision:0,epoch:0,phase:'legacy',data:{participants:{},attempt:null}});
const action=(s,r)=>ownershipTransition(s,{expectedRevision:s.revision,actor:'fixture',reason:'test',...r});
const registered=()=>action(base(),{action:'register',owner:'legacy',processId,inventoryVersion:1,writerKinds:defenderWriterKinds});
test('ownership requires complete inventory, audit, revision and current owner',()=>{
  const s=base();assert.throws(()=>action(s,{action:'begin',attemptId}),/Registered/);
  for(const override of [{writerKinds:[]},{inventoryVersion:2},{owner:'sql'},{processId:'not-a-boot-id'},{expectedRevision:1},{actor:''}])
    assert.throws(()=>action(s,{action:'register',owner:'legacy',processId,inventoryVersion:1,writerKinds:defenderWriterKinds,...override}));
  const r=registered();assert.deepEqual(s,base());assert.equal(r.epoch,0);assert.equal(r.revision,1);
});
test('handoff refuses missing or inconsistent acknowledgements and obsolete attempts',()=>{
  let s=registered();s=action(s,{action:'begin',attemptId});assert.equal(s.phase,'draining');assert.equal(s.epoch,1);
  const finish={action:'finish',attemptId,baselineDigest:hash,candidateDigest:hash,workflowRevision:0};
  assert.throws(()=>action(s,finish),/All registered/);
  for(const override of [{pendingWrites:1},{strictFlush:false},{baselineDigest:'missing'},{processId:attemptId},{attemptId:processId}])
    assert.throws(()=>action(s,{action:'ack',attemptId,processId,baselineDigest:hash,pendingWrites:0,strictFlush:true,...override}));
  s=action(s,{action:'ack',attemptId,processId,baselineDigest:hash,pendingWrites:0,strictFlush:true});
  assert.throws(()=>action(s,{...finish,baselineDigest:'b'.repeat(64)}),/baselines differ/);
  s=action(s,finish);assert.equal(s.phase,'sql');assert.equal(s.epoch,2);assert.deepEqual(s.data.participants,{});
});
test('reversal requires a matching reverse export; abort invalidates every prior writer token',()=>{
  let s={...registered(),phase:'sql'};s.data.participants[processId].owner='sql';
  s=action(s,{action:'begin',attemptId});assert.equal(s.phase,'reversing');
  s=action(s,{action:'ack',attemptId,processId,baselineDigest:hash,pendingWrites:0,strictFlush:true});
  const finish={action:'finish',attemptId,baselineDigest:hash,candidateDigest:hash,workflowRevision:3};
  assert.throws(()=>action(s,finish),/reverse export/);
  const reversed=action(s,{...finish,reverseExportDigest:hash});assert.equal(reversed.phase,'legacy');
  const aborted=action(s,{action:'abort',attemptId});assert.equal(aborted.phase,'sql');assert.equal(aborted.epoch,s.epoch+1);assert.deepEqual(aborted.data.participants,{});
});
