import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {loadConnectorPreview,loadSavedSourceBindings} from '../scripts/connector-preview-loader.mjs';
const build=await loadConnectorPreview(),{selectSavedSourceBindings:select}=await loadSavedSourceBindings();
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[{companyId:'A',tenantId:'private-a',revision:1}],spotlight:[],connections:[],tiles:[]};
const preview=build(metadata,{}),candidate=preview.candidates[0];
function row(c=candidate,scope={}) {
  const hash=createHash('sha256').update(JSON.stringify({candidate:c,sourceEvidence:[]})).digest('hex');
  return{candidate_id:c.id,candidate_hash:hash,imported_hash:hash,provider:c.provider,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',
    proposal:{companyId:'A',tenantId:c.tenantId,datasets:[],targets:[],authority:'findings-primary',...scope}};
}
test('reviewed saved Defender binding selects only its customer and pins tenant/revision',()=>{
  const result=select('A',preview,[row()]);assert.deepEqual(result.sources,['defender']);
  assert.deepEqual(result.defenderConnection,{tenantId:'private-a',revision:1});
  assert.deepEqual(select('B',preview,[]),{sources:[],blocked:[]});
  assert.deepEqual(select('B',preview,[row()]).sources,[]);
  assert.throws(()=>select('UNKNOWN',preview,[]));
});
test('stale, absent, unreviewed and mismatched reviews cannot route',()=>{
  for(const change of [{review_state:'pending-review'},{reviewed_at:null},{source_present:false},{candidate_hash:'0'.repeat(64)},{imported_hash:'0'.repeat(64)}]) {
    const result=select('A',preview,[{...row(),...change}]);assert.equal(result.sources.length,0);assert.equal(result.blocked.length,1);
    assert.doesNotMatch(JSON.stringify(result),/private-a/);
  }
  const changed=build({...metadata,defender:[{companyId:'A',tenantId:'private-a',revision:2}]},{});
  assert.equal(select('A',changed,[row()]).sources.length,0);
  assert.equal(select('A',preview,[{...row(),review_state:'dismissed'}]).blocked.length,0);
});
test('mirrors, duplicate primaries, restrictive filters and wrong tenants do not route',()=>{
  for(const scope of [{authority:'mirror'},{targets:['host-a']},{datasets:['dataset-*']},{tenantId:'private-b'}])
    assert.equal(select('A',preview,[row(candidate,scope)]).sources.length,0);
  assert.equal(select('A',preview,[row(),row()]).sources.length,0);
  assert.equal(select('A',preview,[row(candidate,{authority:'inventory'})]).sources.length,0);
});
test('conflicting customer tenants and environment-only evidence cannot route Defender',()=>{
  const conflicted=build({...metadata,defender:[...metadata.defender,{companyId:'B',tenantId:'private-a',revision:1}]},{});
  const c=conflicted.candidates.find(c=>c.companyId==='A');assert.equal(select('A',conflicted,[row(c)]).sources.length,0);
  const env=build({...metadata,defender:[]},{DEFENDER_CUSTOMER:'A',DEFENDER_TENANT_ID:'private-a',DEFENDER_CLIENT_ID:'fixture',DEFENDER_CLIENT_SECRET:'fixture'});
  assert.equal(select('A',env,[row(env.candidates[0])]).sources.length,0);
});
test('CrowdStrike review produces a private CID guard; malformed tenant is rejected',()=>{
  const cs=build({...metadata,defender:[]},{FALCON_CUSTOMER:'Alpha',FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture'});
  const result=select('A',cs,[row(cs.candidates[0],{tenantId:'declared-cid'})]);
  assert.equal(result.sources.length,0);assert.match(result.blocked[0].reason,/CID/);
  const valid=select('A',cs,[row(cs.candidates[0],{tenantId:'A'.repeat(32)})]);
  assert.deepEqual(valid.sources,['crowdstrike']);assert.equal(valid.spotlightTenant,'a'.repeat(32));
});
