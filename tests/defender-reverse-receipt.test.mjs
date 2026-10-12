import test from 'node:test';
import assert from 'node:assert/strict';
import {reverseReceiptRequest,reverseSnapshotDigest,prepareOwnedReverseExport,verifyOwnedReverseRestore} from '../lib/db/defender-reverse-receipt.mjs';
import {ownershipTransition} from '../lib/db/defender-writer-ownership.mjs';
import {createReverseDigest,reverseValueDigest} from '../lib/db/defender-reverse-digest.mjs';
const id='12345678-1234-1234-1234-123456789abc';
test('reverse receipt requests reject caller-selected generations and declared evidence before storage access',async()=>{
  const r={companyId:'CO-TEST',attemptId:id,expectedRevision:1,actor:'fixture',reason:'test'};
  assert.deepEqual(reverseReceiptRequest(r),r);
  for(const change of [{projectionId:id},{expectedDigest:'a'.repeat(64)},{attemptId:'wrong'},{expectedRevision:-1},{actor:''},{companyId:'other'}]){
    assert.throws(()=>reverseReceiptRequest({...r,...change}));
    await assert.rejects(()=>prepareOwnedReverseExport(null,null,{...r,...change}));
    await assert.rejects(()=>verifyOwnedReverseRestore(null,null,{...r,...change}));
  }
});
test('whole-snapshot receipt digest ignores Map/key order but includes other customers, metadata and nested list ordering',()=>{
  const s={findings:[['b',{id:'b',companyId:'CO-OTHER'}],['a',{id:'a',status:'Open'}]],settings:{list:[1,2],enabled:true}};
  const same={settings:{enabled:true,list:[1,2]},findings:[s.findings[1],s.findings[0]]};
  assert.equal(reverseSnapshotDigest(s),reverseSnapshotDigest(same));
  for(const mutate of [v=>v.findings[0][1].companyId='CO-CHANGED',v=>v.settings.list.reverse(),v=>v.findings.pop()]){
    const copy=structuredClone(s);mutate(copy);assert.notEqual(reverseSnapshotDigest(copy),reverseSnapshotDigest(s));
  }
  assert.throws(()=>reverseSnapshotDigest({...s,findings:[s.findings[0],s.findings[0]]}),/identity/);
});
test('aborting a reverse attempt preserves the selected generation while invalidating writer registration',()=>{
  const lastCompleted={projectionId:id,workflowRevision:4},state={revision:3,epoch:2,phase:'reversing',data:{lastCompleted,participants:{fixture:{}},attempt:{id,origin:'sql'}}};
  const result=ownershipTransition(state,{action:'abort',attemptId:id,expectedRevision:3,actor:'fixture',reason:'retry'});
  assert.deepEqual(result.data.lastCompleted,lastCompleted);assert.deepEqual(result.data.participants,{});assert.equal(result.data.attempt,null);assert.equal(result.epoch,3);assert.equal(result.phase,'sql');
  assert.notEqual(result.data.lastCompleted,lastCompleted);
});
test('incremental digest matches complete snapshot across bucket order and refuses duplicate IDs',()=>{
  const rows=Array.from({length:1001},(_,i)=>[`finding-${i}`,{id:`finding-${i}`,companyId:i%2?'CO-A':'CO-B',nested:[i,i+1]}]);
  const s={findings:rows,assets:[],settings:{enabled:true}},stream=createReverseDigest();
  stream.addValue('settings',s.settings);stream.startMap('assets');stream.startMap('findings');
  for(let bucket=0;bucket<7;bucket++)for(let i=rows.length-1;i>=0;i--)if(i%7===bucket)stream.addEntryHash('findings',rows[i][0],reverseValueDigest(rows[i]));
  assert.equal(stream.finish(),reverseSnapshotDigest(s));
  assert.throws(()=>stream.addEntryHash('findings',rows[0][0],reverseValueDigest(rows[0])),/identity/);
  assert.throws(()=>stream.startMap('assets'),/Duplicate/);
});
