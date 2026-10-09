import assert from 'node:assert/strict';
import test from 'node:test';
import {shadowCveRequest,readDefenderShadowCve,MAX_SHADOW_CVE_BYTES} from '../lib/db/defender-shadow-cve.mjs';
const request={companyId:'CO-A',projectionId:'11111111-1111-1111-1111-111111111111',cve:'cve-2026-1234'};
test('CVE requests require explicit customer and generation with canonical CVE',()=>{
  assert.equal(shadowCveRequest(request).cve,'CVE-2026-1234');
  for(const change of [{companyId:''},{projectionId:'active'},{cve:'CVE-1'},{cve:'CVE-2026-1234 OR true'}])assert.throws(()=>shadowCveRequest({...request,...change}));
});
function clientFor({state='verified',count=1,bytes=10,records=[]}={}){
  const calls=[];return {calls,async query(sql){
    calls.push(sql);
    if(sql.includes('SELECT state,model_version'))return {rows:[{state,model_version:2}]};
    if(sql.startsWith('SELECT f.finding_id FROM'))return {rows:Array.from({length:count},(_,i)=>({finding_id:`F-${i}`}))};
    if(sql.includes('octet_length'))return {rows:[{n:count,bytes:String(bytes)}]};
    if(sql.includes(' AS record'))return {rows:records};
    return {rows:[]};
  }};
}
test('unverified, empty and oversized CVEs reject without transferring evidence',async()=>{
  for(const [options,status] of [[{state:'building'},409],[{count:0},404],[{count:10001},413],[{bytes:MAX_SHADOW_CVE_BYTES},413]]){
    const db=clientFor(options);await assert.rejects(()=>readDefenderShadowCve(db,request),e=>e.status===status);
    assert.equal(db.calls.at(-1),'ROLLBACK');
    assert.ok(!db.calls.some(sql=>sql.startsWith('SELECT f.finding_id AS id')));
  }
});
test('missing or mismatched reconstruction fails the whole read',async()=>{
  for(const records of [[],[{id:'F-0',record:{id:'F-0',companyId:'CO-B'}}]]){
    const db=clientFor({records});await assert.rejects(()=>readDefenderShadowCve(db,request),e=>e.status===409);
    assert.equal(db.calls.at(-1),'ROLLBACK');
  }
});
