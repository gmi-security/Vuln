import assert from 'node:assert/strict';
import test from 'node:test';
import {createShadowCustomerCveReader,readSavedCveContext,readSavedCveEnrichment} from '../lib/db/shadow-customer-cve.mjs';
const company={id:'CO-A',name:'Fixture',isDemo:false},projectionId='11111111-1111-1111-1111-111111111111';
const request={companyId:company.id,cve:'cve-2026-1234'};
const options={enabled:true,resolveCustomer:async()=>({companyId:company.id,company}),bindings:[{companyId:company.id,source:'defender',projectionId}]};
const forbidden={query(){throw new Error('Unexpected database access');}};
const clients={shadowClient:forbidden,enrichmentClient:forbidden,ticketClient:forbidden};
test('disabled and unsupported sources fail before database access',async()=>{
  for(const enabled of [undefined,false,'true',1])await assert.rejects(()=>createShadowCustomerCveReader({...options,enabled})(clients,request),e=>e.status===404);
  for(const bindings of [[],[{...options.bindings[0],source:'crowdstrike'}]])await assert.rejects(()=>createShadowCustomerCveReader({...options,bindings})(clients,request),e=>e.status===409);
  assert.throws(()=>createShadowCustomerCveReader({...options,bindings:[options.bindings[0],options.bindings[0]]}),e=>e.status===409);
});
test('customer resolution rejects demo, wrong and missing customer before reads',async()=>{
  for(const resolved of [null,{companyId:'CO-B',company},{companyId:company.id,company:{...company,id:'CO-B'}},{companyId:company.id,company:{...company,isDemo:true}}]){
    await assert.rejects(()=>createShadowCustomerCveReader({...options,resolveCustomer:async()=>resolved})(clients,request),e=>e.status===404);
  }
});
test('request cannot override a missing trusted projection',async()=>{
  const read=createShadowCustomerCveReader({...options,bindings:[{companyId:company.id,source:'defender'}]});
  await assert.rejects(()=>read(clients,{...request,projectionId}),/Explicit projection scope/);
});
function fake({tables={singles:true,groups:true,enrichment:true},n=0,bytes=0,rows=[]}={}){
  const calls=[];return {calls,async query(sql){calls.push(sql);
    if(sql.includes('to_regclass'))return {rows:[tables]};
    if(sql.includes('row_to_json'))return {rows:[{n,bytes:String(bytes)}]};
    return {rows};
  }};
}
test('missing ticket tables fail closed and never initialize schema',async()=>{
  const db=fake({tables:{singles:null,groups:true}});
  await assert.rejects(()=>readSavedCveContext(db,{companyId:'CO-A',cve:'CVE-2026-1234',assets:['a']}),e=>e.status===503);
  assert.equal(db.calls.at(-1),'ROLLBACK');assert.ok(db.calls.every(s=>!s.includes('CREATE')));
});
test('missing enrichment differs from an empty enrichment result',async()=>{
  assert.equal((await readSavedCveEnrichment(fake({tables:{enrichment:null}}),'CVE-2026-1234')).enrichmentState,'unavailable');
  assert.equal((await readSavedCveEnrichment(fake(),'CVE-2026-1234')).enrichmentState,'not-recorded');
});
test('oversized ticket context rejects before payload transfer',async()=>{
  const db=fake({bytes:8*1024*1024+1});
  await assert.rejects(()=>readSavedCveContext(db,{companyId:'CO-A',cve:'CVE-2026-1234',assets:['a']}),e=>e.status===413);
  assert.equal(db.calls.at(-1),'ROLLBACK');assert.ok(!db.calls.some(sql=>sql.startsWith('SELECT id,state')));
});
