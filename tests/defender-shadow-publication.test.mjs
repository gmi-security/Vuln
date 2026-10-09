import assert from 'node:assert/strict';
import test from 'node:test';
import {shadowPublicationRequest,publishDefenderShadow,readDefenderPublication,readPublishedDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
const request={companyId:'CO-A',projectionId:'11111111-1111-1111-1111-111111111111',expectedRevision:0,actor:'fixture',reason:'Initial comparison'};
test('publication requires an explicit revision and review context',()=>{
  assert.deepEqual(shadowPublicationRequest(request),request);
  for(const change of [{companyId:''},{projectionId:'latest'},{expectedRevision:undefined},{expectedRevision:-1},{expectedRevision:1.5},{actor:' '},{reason:''},{reason:'x'.repeat(501)}])assert.throws(()=>shadowPublicationRequest({...request,...change}));
});
test('publication writer rejects non-disposable storage before a transaction',async()=>{
  for(const metadata of [
    {db:'production',dir:'/home/codex/vuln-recovery/test',listen:''},
    {db:'vuln2_shadow_test_abc',dir:'/var/lib/postgresql',listen:''},
    {db:'vuln2_shadow_test_abc',dir:'/home/codex/vuln-recovery/test',listen:'localhost'},
  ]){
    const calls=[];const client={async query(sql){calls.push(sql);return{rows:[metadata]};}};
    await assert.rejects(()=>publishDefenderShadow(client,request),/Disposable shadow target/);assert.equal(calls.length,1);
  }
});
test('publication reads require scope and reject caller-supplied generations',async()=>{
  const client={query(){assert.fail('Unexpected database access');}};
  await assert.rejects(()=>readDefenderPublication(client,''),e=>e.status===400);
  await assert.rejects(()=>readPublishedDefenderShadow(client,request),e=>e.status===400);
});
