import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';
import { loadConnectorPreview,loadConnectorReview,loadInventoryRouting,loadConnectorStatus } from '../scripts/connector-preview-loader.mjs';
import { parseRegistryArgs,registryFailure } from '../scripts/customer-connector-registry.mjs';
const build=await loadConnectorPreview(),review=await loadConnectorReview(),routing=await loadInventoryRouting(),project=await loadConnectorStatus();
const tenant='11111111-1111-1111-1111-111111111111';
const env={AUTOMATE_BASE_URL:'https://fixture.invalid',AUTOMATE_API_CLIENT_ID:'fixture',AUTOMATE_USERNAME:'fixture',AUTOMATE_PASSWORD:'fixture',
 INTUNE_TENANT_ID:tenant,INTUNE_CLIENT_ID:'fixture',INTUNE_CLIENT_SECRET:'fixture'};
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'},{id:'DEMO',name:'Demo',isDemo:true}],defender:[],spotlight:[],connections:[],tiles:[]};
const preview=build(metadata,env);
function evidence(provider,companyId='A'){
 const c=preview.candidates.find(c=>c.provider===provider),hash=review.connectorDraftEvidence(c,preview.candidates).candidateHash;
 return {candidate_id:c.id,company_id:companyId,provider,source_scope:provider==='intune'?tenant:'17',candidate_hash:hash,binding_hash:hash,imported_hash:hash,
  binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10T00:00:00Z',
  proposal:{companyId,tenantId:provider==='intune'?tenant:'17',authority:'inventory',targets:[],datasets:[]}};
}
test('inventory opt-in is explicit and rejects malformed provider configuration',()=>{
 for(const v of [undefined,'','  '])assert.deepEqual(routing.reviewedInventoryProviders(v),[]);
 assert.deepEqual(routing.reviewedInventoryProviders(' automate, intune '),['automate','intune']);
 for(const v of ['all','true','intune,','automate,automate','crowdstrike'])assert.throws(()=>routing.reviewedInventoryProviders(v));
});
test('operational scope requires current review, exact supported connection, tenant/client ID and inventory-only authority',()=>{
 for(const p of ['automate','intune'])assert.equal(routing.inventoryBindingScope('A',preview,evidence(p)).provider,p);
 for(const edits of [{review_state:'pending-review'},{reviewed_at:null},{imported_hash:'0'.repeat(64)},{source_present:false},
  {proposal:{...evidence('automate').proposal,companyId:'B'}},
  ...['0','017','1 OR 1','9007199254740992'].map(tenantId=>({proposal:{...evidence('automate').proposal,tenantId}})),
  ...[{targets:['private.host']},{datasets:['private-*']},{authority:'findings-primary'}].map(p=>({proposal:{...evidence('automate').proposal,...p}}))])
  assert.throws(()=>routing.inventoryBindingScope('A',preview,{...evidence('automate'),...edits}));
 assert.throws(()=>routing.inventoryBindingScope('B',preview,evidence('intune')));
 assert.throws(()=>routing.inventoryBindingScope('DEMO',preview,evidence('intune','DEMO')));
 const changed=build(metadata,{...env,AUTOMATE_BASE_URL:'https://different.invalid'});
 assert.throws(()=>routing.inventoryBindingScope('A',changed,evidence('automate')));
 assert.throws(()=>routing.inventoryBindingScope('A',preview,{...evidence('intune'),proposal:{...evidence('intune').proposal,tenantId:'22222222-2222-2222-2222-222222222222'}}));
});
test('customer status distinguishes approved, opted-in, stale and disabled routes without private scope or another customer',()=>{
 const row=evidence('intune'),c=preview.candidates.find(c=>c.id===row.candidate_id);
 const draft={id:c.id,candidate:c,candidate_hash:row.candidate_hash,proposal:row.proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at};
 const approved=routing.inventoryRoutingStatus(row,preview,'');assert.match(approved.routing,/switch is off/);
 const on=routing.inventoryRoutingStatus(row,preview,'intune');assert.match(on.routing,/switch is on/);
 const response=project('A',preview,[draft],true,undefined,[on]);assert.equal(response.items[0].review,'Inventory route approved');
 assert.doesNotMatch(JSON.stringify(response),new RegExp(tenant+'|source_scope|binding_hash|PRIVATE|fixture.invalid'));
 assert.equal(project('B',preview,[draft],true,undefined,[on]).items.length,0);
 for(const edit of [{current_binding_revision:2},{binding_hash:'0'.repeat(64)},{source_scope:'different'},{imported_hash:'0'.repeat(64)}])
  assert.match(routing.inventoryRoutingStatus({...row,...edit},preview,'intune').review,/needs review/);
 assert.match(routing.inventoryRoutingStatus({...row,enabled:false},preview,'intune').review,/disabled/);
 assert.match(routing.inventoryRoutingStatus(row,preview,'invalid').review,/needs review/);
});
test('operator commands are explicit and errors never expose underlying database details',()=>{
 assert.equal(parseRegistryArgs(['route-inventory','--input','fixture.json']).command,'route-inventory');
 assert.equal(parseRegistryArgs(['export-inventory-routes','--company','A','--output','fixture.json']).command,'export-inventory-routes');
 for(const args of [['route-inventory'],['route-inventory','--input','x','--enabled','true'],['export-inventory-routes','--company','A']])assert.throws(()=>parseRegistryArgs(args));
 assert.doesNotMatch(registryFailure({code:'23505',message:'private source ID'}),/private/);
 assert.match(registryFailure({code:'42P01'}),/does not create tables/);
});
test('runtime switch off returns legacy mode without DB, metadata, schema or network access; bad switch cannot fall back',async()=>{
 let connects=0;
 const code=ts.transpileModule(await readFile('lib/customer-inventory-routing-server.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(code,{importModuleDynamically:()=>{throw Error('Unexpected metadata import');}});
 await mod.link(name=>{
  const values=name==='./persist'?{applicationDatabase:()=>{connects++;throw Error('Unexpected DB');}}:routing;
  assert.ok(['./persist','./customer-inventory-routing'].includes(name));
  return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
 });await mod.evaluate();
 const before=process.env.VULN_REVIEWED_INVENTORY_PROVIDERS;
 try{
  delete process.env.VULN_REVIEWED_INVENTORY_PROVIDERS;
  assert.equal(await mod.namespace.loadReviewedInventoryRoutes('automate'),null);
  process.env.VULN_REVIEWED_INVENTORY_PROVIDERS='automate';assert.equal(await mod.namespace.loadReviewedInventoryRoutes('intune'),null);
  process.env.VULN_REVIEWED_INVENTORY_PROVIDERS='typo';await assert.rejects(()=>mod.namespace.loadReviewedInventoryRoutes('automate'));
  assert.equal(connects,0);
 }finally{if(before===undefined)delete process.env.VULN_REVIEWED_INVENTORY_PROVIDERS;else process.env.VULN_REVIEWED_INVENTORY_PROVIDERS=before;}
});
test('enabled runtime wrapper collects current metadata, returns validated routes and redacts storage failures without fallback',async()=>{
 let released=0,queries=[],broken=false;
 const client={release(){released++;},async query(sql){queries.push(sql);if(broken)throw Error('private connection URL and password');
  return {rows:sql.includes('FROM public.customer_inventory_routes')?[evidence('automate')]:[]};}};
 const pool={connect:async()=>client};
 async function synthetic(values){
  const module=new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
  await module.link(()=>{throw Error('Unexpected fixture dependency');});await module.evaluate();return module;
 }
 const code=ts.transpileModule(await readFile('lib/customer-inventory-routing-server.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(code,{importModuleDynamically:async name=>{
  if(name==='./customer-connector-preview')return synthetic({buildConnectorPreview:build});
  assert.equal(name,'./db/connector-metadata.mjs');
  return synthetic({readApplicationConnectorMetadata:async c=>{assert.equal(c,client);return metadata;}});
 }});
 await mod.link(name=>synthetic(name==='./persist'?{applicationDatabase:()=>pool}:routing));await mod.evaluate();
 const values={...env,VULN_REVIEWED_INVENTORY_PROVIDERS:'automate'},before=Object.fromEntries(Object.keys(values).map(k=>[k,process.env[k]]));
 try{
  Object.assign(process.env,values);
  const result=await mod.namespace.loadReviewedInventoryRoutes('automate');
  assert.deepEqual(result.map(r=>[r.companyId,r.sourceScope]),[['A','17']]);assert.equal(released,2);
  assert.ok(queries.includes('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  assert.ok(queries.every(sql=>!/^(INSERT|UPDATE|CREATE|ALTER|DELETE)/.test(sql)));
  broken=true;await assert.rejects(()=>mod.namespace.loadReviewedInventoryRoutes('automate'),e=>{
   assert.match(e.message,/No legacy routing was used/);assert.doesNotMatch(e.message,/private|password|URL/);return true;
  });
 }finally{for(const [k,v]of Object.entries(before)){if(v===undefined)delete process.env[k];else process.env[k]=v;}}
});
