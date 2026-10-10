import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import {loadConnectorPreview,loadConnectorReview,loadSpotlightRouting,loadConnectorStatus} from '../scripts/connector-preview-loader.mjs';
import {parseRegistryArgs,registryFailure} from '../scripts/customer-connector-registry.mjs';
const build=await loadConnectorPreview(),review=await loadConnectorReview(),routing=await loadSpotlightRouting();
const env={FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:'Alpha'};
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[],spotlight:[],connections:[],tiles:[]};
const preview=build(metadata,env),c=preview.candidates.find(c=>c.provider==='crowdstrike');
const hash=review.connectorDraftEvidence(c,preview.candidates).candidateHash;
const row={candidate_id:c.id,company_id:'A',provider:'crowdstrike',source_scope:'a'.repeat(32),candidate_hash:hash,binding_hash:hash,imported_hash:hash,
 binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',
 proposal:{companyId:'A',tenantId:'a'.repeat(32),authority:'findings-primary',targets:[],datasets:[]}};
const read=rows=>routing.createSpotlightRoutingStore({connect:async()=>({query:async sql=>({rows:String(sql).includes('SELECT r.*')?rows:[]}),release(){}})}).read('crowdstrike',async()=>preview);
test('Spotlight switch is separate and rejects other providers or malformed configuration',()=>{
 for(const raw of [undefined,'',' '])assert.deepEqual(routing.reviewedSpotlightProviders(raw),[]);
 assert.deepEqual(routing.reviewedSpotlightProviders('crowdstrike'),['crowdstrike']);
 for(const raw of ['all','true','intune','crowdstrike,','crowdstrike,crowdstrike'])assert.throws(()=>routing.reviewedSpotlightProviders(raw));
});
test('Spotlight requires primary findings approval, fresh evidence and exactly one unrestricted CID',()=>{
 assert.equal(routing.spotlightBindingScope('A',preview,row).sourceScope,'a'.repeat(32));
 for(const patch of [{review_state:'draft'},{source_present:false},{reviewed_at:null},{imported_hash:'0'.repeat(64)},
  ...[{authority:'inventory'},{authority:'mirror'},{authority:'query-only'},{targets:['host']},{datasets:['data']},{tenantId:'bad'},{companyId:'B'}].map(p=>({proposal:{...row.proposal,...p}}))])
  assert.throws(()=>routing.spotlightBindingScope('A',preview,{...row,...patch}));
 assert.throws(()=>routing.spotlightBindingScope('A',build(metadata,{...env,FALCON_CLOUD:'us-2'}),row));
});
test('approval revisions pin resumable generation identity and stale routes fail without partial output',async()=>{
 const first=(await read([row]))[0];assert.match(first.bindingKey,/^[a-f0-9]{64}$/);
 assert.notEqual((await read([{...row,revision:2}]))[0].bindingKey,first.bindingKey);
 for(const patch of [{binding_revision:2},{binding_hash:'0'.repeat(64)},{source_scope:'b'.repeat(32)},{enabled:false}])await assert.rejects(()=>read([{...row,...patch}]));
 await assert.rejects(()=>read([row,row]),/conflicting/);
 assert.deepEqual(await read([]),[]);
});
test('Spotlight operator input is explicit and database errors are redacted',()=>{
 assert.equal(parseRegistryArgs(['route-spotlight','--input','private.json']).command,'route-spotlight');
 assert.equal(parseRegistryArgs(['export-spotlight-routes','--company','A','--output','private.json']).command,'export-spotlight-routes');
 assert.throws(()=>parseRegistryArgs(['route-spotlight']));
 assert.doesNotMatch(registryFailure(Error('PRIVATE_SECRET')),/PRIVATE_SECRET/);
});
const selectionModule=new SourceTextModule(ts.transpileModule(await readFile('lib/spotlight-import.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
await selectionModule.link(()=>{throw Error('Unexpected runtime import');});await selectionModule.evaluate();
test('reviewed selection uses connection reference and customer ID independently of display names',async()=>{
 const select=selectionModule.namespace.selectReviewedSpotlightTenant,route=(await read([row]))[0];
 const configs=[{sourceRef:'environment:FALCON',label:'Wrong display name',customerName:'Beta'}];
 const picked=select(configs,metadata.companies,[route]);assert.equal(picked.companyId,'A');assert.equal(picked.reviewedScope.cid,row.source_scope);
 for(const [cs,companies,routes,requested] of [[configs,metadata.companies,[],undefined],[configs,metadata.companies,[route],'B'],
  [configs,[],[route]],[[...configs,...configs].flat(),metadata.companies,[route]],[[{sourceRef:'environment:FALCON_2'}],metadata.companies,[route]],
  [configs,metadata.companies,[route,route]]])assert.throws(()=>select(cs,companies,routes,requested));
});
test('disabled runtime wrapper does not read database or dynamically load metadata; opted-in missing storage fails closed',async()=>{
 let reads=0;const old=process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS;
 const mod=new SourceTextModule(ts.transpileModule(await readFile('lib/customer-spotlight-routing-server.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
 await mod.link(spec=>new SyntheticModule(spec==='./persist'?['applicationDatabase']:Object.keys(routing),function(){
  if(spec==='./persist')this.setExport('applicationDatabase',()=>{reads++;return null;});else for(const k of Object.keys(routing))this.setExport(k,routing[k]);
 }));await mod.evaluate();
 try {delete process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS;assert.equal(await mod.namespace.loadReviewedSpotlightRoutes('crowdstrike'),null);assert.equal(reads,0);
  process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS='crowdstrike';await assert.rejects(()=>mod.namespace.loadReviewedSpotlightRoutes('crowdstrike'),/unavailable/);assert.equal(reads,1);
 }finally{if(old===undefined)delete process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS;else process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS=old;}
});

test('customer status reports inventory and Spotlight independently without exposing CID or approval pins',async()=>{
 const project=await loadConnectorStatus(),draft={id:c.id,candidate:c,candidate_hash:hash,proposal:row.proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at};
 for(const [raw,patch,expected] of [['',{},/switch is off/],['crowdstrike',{},/switch is on/],['crowdstrike',{current_binding_revision:2},/stale or invalid/],['crowdstrike',{enabled:false},/disabled/]]){
  const status=routing.spotlightRoutingStatus({...row,...patch},preview,raw);
  const result=project('A',preview,[draft],true,undefined,[{id:c.id,review:'Inventory route approved',routing:'Inventory approval only.'}],[status]);
  assert.match(result.items[0].data.routing,expected);assert.match(result.items[0].review,/Inventory route approved/);
  assert.doesNotMatch(JSON.stringify(result),new RegExp(row.source_scope+'|bindingKey|candidate_hash|fixture.invalid'));
  assert.equal(project('B',preview,[draft],true,undefined,[],[status]).items.length,0);
 }
});
