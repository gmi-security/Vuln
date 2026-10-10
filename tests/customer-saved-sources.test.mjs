import assert from 'node:assert/strict';
import test from 'node:test';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
const require=createRequire(import.meta.url);
const {savedSourcePolicy,createCustomerSavedSources,SavedSourceError}=require('../.worker-build/spotlight-summary/lib/customer-saved-sources.js');
const query=value=>new URLSearchParams(value);
test('invalid policy never falls back to a shared source',()=>{
  assert.deepEqual(savedSourcePolicy(undefined),{});
  for(const value of ['null','[]','bad','{"*": ["defender"]}','{"CO-A":["elastic"]}','{"CO-A":["defender","defender"]}'])assert.throws(()=>savedSourcePolicy(value));
});
test('customer setup, source scope and pagination are explicit and bounded',async()=>{
  const calls=[];
  const service=createCustomerSavedSources({policy:savedSourcePolicy('{"CO-A":["defender"],"CO-B":["crowdstrike"]}'),
    companies:async()=>[{id:'CO-A',name:'Alpha'},{id:'CO-B',name:'Beta'},{id:'CO-EMPTY',name:'Empty'},{id:'CO-DEMO',name:'Demo',isDemo:true}],
    read:Object.fromEntries(['defender','crowdstrike'].map(source=>[source,async request=>{calls.push({...request,source});return{companyId:request.companyId,source,state:'summary-pending'};}]))});
  assert.equal((await service.get(query('setup=1'))).companies.length,3);assert.equal(calls.length,0);
  assert.deepEqual(await service.get(query('companyId=CO-EMPTY')),{companyId:'CO-EMPTY',sources:[]});
  for(const value of ['','setup=1&companyId=CO-A','companyId=CO-DEMO','companyId=CO-X','companyId=CO-A&source=crowdstrike','companyId=CO-A&source=elastic','companyId=CO-A&source=defender&offset=2junk','companyId=CO-A&source=defender&offset=1000001'])await assert.rejects(()=>service.get(query(value)));
  assert.equal(calls.length,0);await service.get(query('companyId=CO-A&source=defender&offset=50'));
  assert.equal(calls[0].companyId,'CO-A');assert.equal(calls[0].limit,50);assert.equal(calls[0].offset,50);assert.equal(calls[0].staleAfterMs,36*3600000);
});
test('wrong-customer/source responses and duplicate identities are rejected',async()=>{
  const deps={policy:{'CO-A':['defender']},companies:async()=>[{id:'CO-A',name:'A'}],read:{defender:async()=>({companyId:'CO-B',source:'defender'}),crowdstrike:()=>assert.fail()}};
  await assert.rejects(()=>createCustomerSavedSources(deps).get(query('companyId=CO-A&source=defender')),e=>e.status===503);
  await assert.rejects(()=>createCustomerSavedSources({...deps,companies:async()=>[{id:'CO-A',name:'A'},{id:'CO-A',name:'Other'}]}).get(query('setup=1')),e=>e.status===503);
});
async function routeHarness({enabled=true,ui=true,authError=false,mode='allowlist',sources=['defender']}={}){
  const calls=[];class DashboardError extends Error{constructor(message,status){super(message);this.status=status;}}
  const stubs={
    '@/lib/elastic-dashboard-http':{dashboardAccess:async()=>{calls.push('auth');if(authError)throw new DashboardError('Unauthorized',401);},dashboardJson:value=>({status:200,value}),dashboardFailure:error=>({status:error.status??503})},
    '@/lib/elastic-dashboard':{DashboardError},'@/lib/remediation-server':{remediationUiEnabled:()=>ui},
    '@/lib/persist':{applicationDatabase:()=>{calls.push('db');return{connect:async()=>({release:()=>{}})};}},
    '@/lib/db/connector-metadata.mjs':{readSavedApplicationCompanies:async()=>{calls.push('companies');return[{id:'CO-A',name:'A'}];}},
    '@/lib/customer-saved-sources':{savedSourcePolicy,createCustomerSavedSources,SavedSourceError},
    '@/lib/customer-saved-source-bindings':{createSavedSourceBindingSelector:()=>async company=>{calls.push('registry:'+company);return{sources,blocked:[],defenderConnection:{tenantId:'private-a',revision:1}};}},
    '@/lib/defender-source-read-model':{createDefenderSourceReader:()=>async req=>{calls.push('defender');return{companyId:req.companyId,source:'defender',state:'no-completed-import'};}},
    '@/lib/spotlight-summary-store':{createSpotlightSummaryStore:()=>({read:()=>assert.fail('wrong reader')})},
  };
  const code=ts.transpileModule(await readFile('app/api/elastic-dashboard/customer-saved-sources/route.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code);await mod.link(spec=>{assert.ok(stubs[spec],spec);return new SyntheticModule(Object.keys(stubs[spec]),function(){for(const [k,v]of Object.entries(stubs[spec]))this.setExport(k,v);});});await mod.evaluate();
  const old=process.env.VULN_SAVED_SOURCE_READS,oldMap=process.env.VULN_SAVED_SOURCE_READ_CUSTOMERS,oldMode=process.env.VULN_SAVED_SOURCE_SELECTION;
  process.env.VULN_SAVED_SOURCE_SELECTION=mode;
  process.env.VULN_SAVED_SOURCE_READS=enabled?'true':'false';process.env.VULN_SAVED_SOURCE_READ_CUSTOMERS='{"CO-A":["defender"]}';
  try{return {calls,response:await mod.namespace.GET(new Request('http://test/api?companyId=CO-A&source=defender'))};}
  finally{if(old===undefined)delete process.env.VULN_SAVED_SOURCE_READS;else process.env.VULN_SAVED_SOURCE_READS=old;if(oldMap===undefined)delete process.env.VULN_SAVED_SOURCE_READ_CUSTOMERS;else process.env.VULN_SAVED_SOURCE_READ_CUSTOMERS=oldMap;if(oldMode===undefined)delete process.env.VULN_SAVED_SOURCE_SELECTION;else process.env.VULN_SAVED_SOURCE_SELECTION=oldMode;}
}
test('route requires existing authorization and both gates before database access',async()=>{
  for(const options of [{enabled:false},{ui:false},{authError:true}]){const h=await routeHarness(options);assert.equal(h.response.status,options.authError?401:404);assert.deepEqual(h.calls,['auth']);}
  const h=await routeHarness();assert.equal(h.response.status,200);assert.deepEqual(h.calls,['auth','db','companies','defender']);
});

test('registry selection replaces the allowlist without fallback and validates mode before DB access',async()=>{
  const allowed=await routeHarness({mode:'registry'});assert.equal(allowed.response.status,200);
  assert.deepEqual(allowed.calls,['auth','db','companies','registry:CO-A','defender']);
  const denied=await routeHarness({mode:'registry',sources:[]});assert.equal(denied.response.status,404);
  assert.ok(!denied.calls.includes('defender'));
  const invalid=await routeHarness({mode:'registrry'});assert.equal(invalid.response.status,503);assert.deepEqual(invalid.calls,['auth']);
});

test('selection guards stay server-side and are passed only to the selected reader',async()=>{
  const guard={tenantId:'private-a',revision:2},calls=[];
  const service=createCustomerSavedSources({policy:{},companies:async()=>[{id:'CO-A',name:'A'}],
    select:async()=>({sources:['defender'],blocked:[],defenderConnection:guard}),
    read:{defender:async request=>{calls.push(request);return{companyId:'CO-A',source:'defender'};},crowdstrike:()=>assert.fail()}});
  assert.deepEqual(await service.get(query('companyId=CO-A')),{companyId:'CO-A',sources:['defender'],blocked:[]});
  await service.get(query('companyId=CO-A&source=defender&tenantId=other&revision=9'));
  assert.deepEqual(calls[0].defenderConnection,guard);
});
