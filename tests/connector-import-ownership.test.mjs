// Actual store import entrypoints; vendor/persistence transports are fixtures.
// No database, source API, scan, message or ticket is used.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import test from 'node:test';
import ts from 'typescript';
const fail=()=>{throw new Error('Unexpected external operation in ownership fixture');};
globalThis.fetch=fail;
const ROOT=resolve('.'),modules=new Map();
let sfScans=[],sfReads=0,arFindings=[],folders=[],scans=[],clients=[],deviceReads=0,configs=[];
let routes=null,routeError=false,clientReads=0,requestedClients=[],afterDevices=()=>{},intuneReads=0,intuneConfigUsed;
let arIncomplete=0;
let osintRoutes={spiderfoot:null,artemis:null},osintError=false,osintLaunches=[],sfFindings=[],arReads=[],sfScopes=[],afterOsint=()=>{};
let activeRoutes={zap:null,vulners:null},activeLaunches=[],activeResults=[],activeStatus=100,activeFail=false,afterActive=()=>{},activeConfig={baseUrl:'https://active.fixture.invalid',apiKey:'fixture'};
let scannerRouteLoads=0,nessusRosterReads=0,nessusStatusReads=0,nessusStatus="completed";
let scannerRoutes=null,scannerError=false,nessusResults={findings:[],scannedHosts:[]},nessusReads=[],nessusLaunches=[],nessusControls=[],afterNessus=()=>{};
let spotlightRoutes=null,spotlightFailure=false,spotlightRuns=[],afterSpotlight=()=>{},spotlightPromotions=0;
let tidalReads=0,tidalOptions,tidalResult,crowdstrikeReads=[],falconFailure;
const tenantId='11111111-1111-1111-1111-111111111111';
const device={externalId:'device-1',hostname:'managed-host',ipAddresses:[],os:'Windows',owner:'',tags:[],criticality:'Normal',exposure:'Internal'};
const mocks={
 'lib/zap.ts':{zapConfig:()=>activeConfig,zapCreateScope:async(config,target)=>({config,origin:target,name:'fixture',id:'1'}),zapRemoveScope:async()=>{},
  zapStartSpider:async(target,scope)=>{activeLaunches.push({provider:'zap',target,scope});return '1';},zapSpiderStatus:async()=>{if(activeFail)throw Error('Fixture failed');return activeStatus;},
  zapStartActiveScan:async()=> '2',zapActiveScanStatus:async()=>activeStatus,zapFetchReport:async()=>{afterActive();return activeResults;}},
 'lib/vulners.ts':{vulnersBridgeConfig:()=>activeConfig,vulnersBridgeStartScan:async(target,name,scope)=>{activeLaunches.push({provider:'vulners',target,scope});if(activeFail)throw Error('Fixture failed');return {jobId:'job',status:'complete'};},
  vulnersBridgeJobStatus:async()=>({status:'complete'}),vulnersBridgeJobFindings:async()=>{afterActive();return activeResults;}},
 'lib/customer-spotlight-routing-server.ts':{loadReviewedSpotlightRoutes:async()=>{if(spotlightFailure)throw Error('Spotlight route unavailable');return spotlightRoutes;}},
 'lib/spotlight-resumable-import.ts':{runPartitionedSpotlightImport:async(selection,_partitions,deps)=>{spotlightRuns.push(selection);afterSpotlight();return {...await deps.complete('fixture',selection.tenantKey,selection.reviewedScope),skipped:0};}},
 'lib/spotlight-record-store.ts':{completeResumableSpotlightRun:async()=>{spotlightPromotions++;return {findingsImported:1,hostsAffected:1};}},
 'lib/persist.ts':{persistenceEnabled:()=>false,strictPlatformPersistence:()=>false,applicationDatabase:()=>null},
 'lib/nessus.ts':{nessusConfig:()=>({url:'https://fixture.invalid'}),nessusListFolders:async()=>folders,nessusListScans:async(_config,folder)=>{nessusRosterReads++;return scans.filter(s=>folder===undefined||s.folderId===folder);},
  nessusImportFindings:async(id,_budget,scope)=>{nessusReads.push({id,scope});afterNessus();return nessusResults;},
  nessusLaunchScan:async(name,targets,profile,scope)=>{nessusLaunches.push({name,targets,profile,scope});return {nessusScanId:10};},
  nessusScanControl:async(id,action)=>{nessusControls.push({id,action});},nessusScanStatus:async()=>{nessusStatusReads++;return {status:nessusStatus,progress:50};}},
 'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async(provider)=>{if(provider==="zap"||provider==="vulners")return activeRoutes[provider];if(provider!=="nessus"){if(osintError)throw Error("OSINT routing unavailable");return osintRoutes[provider];}scannerRouteLoads++;if(scannerError)throw Error('Scanner route unavailable');return scannerRoutes;}},
 'lib/spiderfoot.ts':{spiderfootConfig:()=>({url:'https://sf.fixture.invalid',insecure:false}),spiderfootListScans:async()=>sfScans,spiderfootImportFindings:async(id,scope)=>{sfReads++;sfScopes.push(scope);afterOsint();return sfFindings;},spiderfootStartScan:async(name,target,usecase,scope)=>{osintLaunches.push({provider:'spiderfoot',target,scope});afterOsint();return 'launched';}},
 'lib/artemis.ts':{artemisCollectReviewedFindings:async(scope)=>{arReads.push(scope);afterOsint();return {findings:arFindings.filter(f=>f.tag===scope.tag),incompleteAnalyses:arIncomplete};},artemisConfig:()=>({url:'https://ar.fixture.invalid'}),artemisImportFindings:async(scope)=>{arReads.push(scope);afterOsint();return scope?arFindings.filter(f=>f.tag===scope.tag):arFindings;},artemisAddTargets:async(targets,tag,scope)=>{osintLaunches.push({provider:'artemis',targets,tag,scope});afterOsint();return {ok:true,ids:['launched']};}},
 'lib/customer-inventory-routing-server.ts':{loadReviewedInventoryRoutes:async()=>{if(routeError)throw Error('Routing needs renewed approval');return routes;}},
 'lib/connectwise-automate.ts':{automateConfig:()=>({}),automateListClients:async()=>{clientReads++;return clients;},automateListComputers:async(_config,id)=>{deviceReads++;requestedClients.push(id);afterDevices();return[device];}},
 'lib/intune.ts':{intuneConfig:()=>({tenantId}),intuneListAssets:async(config)=>{intuneReads++;intuneConfigUsed=config;afterDevices();return[device];}},
 'lib/tidal.ts':{tidalConfig:()=>({url:'https://fixture.invalid'}),tidalListAssets:async(_p,options)=>{tidalReads++;tidalOptions=options;afterDevices();return tidalResult;}},
 'lib/crowdstrike.ts':{falconConfigs:()=>configs,falconListAssets:async(config,_p,scope)=>{crowdstrikeReads.push({config,scope});if(falconFailure && falconFailure===config.sourceRef)throw Error('Fixture CID mismatch');afterDevices();return[device];},SPOTLIGHT_DISCOVERY_PARTITIONS:[]},
};
async function getModule(path){
 path=resolve(path);if(modules.has(path))return modules.get(path);
 const promise=(async()=>{
   const code=ts.transpileModule(await readFile(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
   const key=Object.keys(mocks).find(key=>resolve(key)===path);
   if(key){
     const names=[...code.matchAll(/export\s+(?:async\s+)?(?:function\s*\*?|const|let|class)\s*(\w+)/g)].map(m=>m[1]);
     return new SyntheticModule(names,function(){for(const name of names)this.setExport(name,mocks[key][name]??fail);},{identifier:path});
   }
   return new SourceTextModule(code,{identifier:path});
 })();modules.set(path,promise);return promise;
}
async function linker(name,parent){
 if(name.startsWith('.'))return getModule(resolve(dirname(parent.identifier),name.endsWith(".mjs")?name:`${name}.ts`));
 if(name.startsWith('@/'))return getModule(resolve(ROOT,`${name.slice(2)}.ts`));
 const imported=await import(name),values=name==='rrule'?{...imported.default,...imported}:imported;
 return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
}
const module=await getModule('lib/store.ts');await module.link(linker);await module.evaluate();const store=module.namespace;
const company=(id,name,kind='client')=>({id,name,kind,industry:'Test',createdAt:'2026-10-01T00:00:00Z',contactName:'',contactEmail:''});
const acme=company('CO-A','Acme'),beacon=company('CO-B','Beacon');
function fixture(companies=[acme,beacon]){
 activeRoutes={zap:null,vulners:null};activeLaunches=[];activeResults=[];activeStatus=100;activeFail=false;afterActive=()=>{};activeConfig={baseUrl:'https://active.fixture.invalid',apiKey:'fixture'};
 arIncomplete=0;osintRoutes={spiderfoot:null,artemis:null};osintError=false;osintLaunches=[];sfFindings=[];arReads=[];sfScopes=[];afterOsint=()=>{};
 scannerRouteLoads=0;nessusRosterReads=0;nessusStatusReads=0;nessusStatus="completed";
 scannerRoutes=null;scannerError=false;nessusResults={findings:[],scannedHosts:[]};nessusReads=[];nessusLaunches=[];nessusControls=[];afterNessus=()=>{};
 spotlightRoutes=null;spotlightFailure=false;spotlightRuns=[];afterSpotlight=()=>{};spotlightPromotions=0;
 sfScans=[];sfReads=0;arFindings=[];folders=[];scans=[];clients=[];deviceReads=0;configs=[];
 routes=null;routeError=false;clientReads=0;requestedClients=[];afterDevices=()=>{};intuneReads=0;intuneConfigUsed=undefined;
 tidalReads=0;tidalOptions=undefined;tidalResult={assets:[],errors:[],skippedCompanies:0};crowdstrikeReads=[];falconFailure=undefined;
 const s={companies:new Map(companies.map(c=>[c.id,c])),folders:new Map(),scans:new Map(),findings:new Map(),assets:new Map(),
  compensatingControls:new Map(),identityAliases:new Map(),settings:{autoScanNewAssets:false,
    schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},
  meta:{nessusBackfillCorrected:true},seeded:true,counter:1000};globalThis.__vulnStore=s;return s;
}
function unchanged(s){assert.equal(s.scans.size,0);assert.equal(s.findings.size,0);assert.equal(s.assets.size,0);}
const arItem=(tag,asset='host.example')=>({tag,asset,cve:'OSINT-TEST',severity:'Low',cvss:0,title:'Exposure',category:'Test',description:''});
test('SpiderFoot and Burp refuse tied customer names independently of insertion order; unique match still imports',async()=>{
 for(const order of [[acme,{...acme,id:'CO-C'}],[{...acme,id:'CO-C'},acme]]){
  const s=fixture(order);sfScans=[{id:'sf-1',name:'Acme',target:'acme.example',status:'FINISHED'}];
  const result=await store.importFromSpiderfoot();assert.equal(result.scansImported,0);assert.match(result.skipped[0].reason,/unambiguous/);assert.equal(sfReads,0);
  assert.equal(store.importBurpFindings([{asset:'acme.example',path:'/'}]).skipped,1);unchanged(s);
 }
 const s=fixture();sfScans=[{id:'sf-1',name:'Acme',target:'acme.example',status:'FINISHED'}];
 assert.equal((await store.importFromSpiderfoot()).scansImported,1);assert.equal([...s.scans.values()][0].companyId,acme.id);assert.equal(sfReads,1);
});
test('Nmap cannot use a name guess to override conflicting inventory ownership',()=>{
 const s=fixture();
 for(const c of [acme,beacon])s.assets.set(c.id,{...device,id:c.id,identifier:'acme-host',hostname:'acme-host',ipAddresses:['10.0.0.1'],companyId:c.id,companyName:c.name,source:'manual'});
 const before=structuredClone([...s.assets]);
 const result=store.importNmapScan([{host:'acme-host',ip:'10.0.0.1',ports:[],os:'NewOS'}]);
 assert.equal(result.skipped,1);assert.equal(result.hostsProcessed,0);assert.deepEqual([...s.assets],before);assert.equal(s.scans.size,0);
});
test('Artemis keeps existing scan ownership and does not fall back from ambiguous tags or explicit aliases',async()=>{
 for(const [companies,tag,asset] of [
  [[company('CO-A','Acme East'),company('CO-B','Acme West')],'Acme','east.example'],
  [[company('CO-A','GMI Scans East'),company('CO-B','GMI Scans West')],'sonar','east.example']]){
  const s=fixture(companies);arFindings=[arItem(tag,asset)];assert.equal((await store.importFromArtemis()).tagsProcessed,0);unchanged(s);
 }
 const s=fixture();const existing={id:'SCAN-OLD',companyId:beacon.id,externalRef:'artemis:Acme',completedAt:'2026-01-01'};
 s.scans.set(existing.id,existing);arFindings=[arItem('Acme')];
 const result=await store.importFromArtemis();assert.equal(result.tagsProcessed,0);assert.match(result.skipped[0].reason,/different company/);
 assert.equal(s.findings.size,0);assert.equal(existing.completedAt,'2026-01-01');assert.equal(s.folders.size,0);
});
test('Tidal rejects ambiguous normalized names without creating companies and preserves upstream errors',async()=>{
 const s=fixture([acme,company('CO-C',' ACME ')]);const errors=['upstream incomplete'];
 const result=await store.importTidalInventory([{...device,customer:'Acme'},{...device,externalId:'device-2',customer:'Acme'}],errors);
 unchanged(s);assert.equal(result.companiesCreated,0);assert.equal(s.companies.size,2);assert.equal(result.errors.length,2);assert.deepEqual(errors,['upstream incomplete']);
 fixture();assert.equal((await store.importTidalInventory([{...device,customer:'Acme'}])).assetsUpserted,1);
});
test('Automate refuses duplicate names and ambiguous internal alias before fetching devices; valid clients continue',async()=>{
 let s=fixture([acme,company('CO-C',' ACME '),beacon]);clients=[{id:1,name:'Acme'},{id:2,name:'Beacon'}];
 let result=await store.importFromAutomate();assert.equal(result.assetsUpserted,1);assert.equal(deviceReads,1);assert.equal(result.errors.length,1);
 assert.equal([...s.assets.values()][0].companyId,beacon.id);
 s=fixture([company('CO-A','Internal East','internal'),company('CO-B','Internal West','internal')]);clients=[{id:1,name:'Global Market Innovators, Inc.'}];
 result=await store.importFromAutomate();assert.equal(deviceReads,0);assert.equal(result.errors.length,1);unchanged(s);assert.equal(s.companies.size,2);
});

const route=(provider,companyId,sourceScope)=>({provider,companyId,sourceScope,candidateId:'a'.repeat(64),revision:1});
test('reviewed Tidal uses server company IDs, limits collection and rescoring, and blocks name-only CSV bypass',async()=>{
 const s=fixture([acme,company('CO-C',' ACME '),beacon]);routes=[route('tidal',beacon.id,'Vendor-A')];
 tidalResult={assets:[{...device,customer:'Acme',sourceCompanyId:'Vendor-A'}],errors:['One unavailable source'],skippedCompanies:2};
 const finding={id:'keep',companyId:acme.id,realRisk:73};s.findings.set('keep',finding);
 let result=await store.importFromTidal();assert.equal(result.assetsUpserted,1);assert.equal(result.companiesCreated,0);assert.equal(result.skipped,2);
 assert.deepEqual([...tidalOptions.companyIds],['Vendor-A']);assert.equal(tidalOptions.config.url,'https://fixture.invalid');
 assert.equal([...s.assets.values()][0].companyId,beacon.id);assert.deepEqual(result.errors,['One unavailable source']);assert.equal(finding.realRisk,73);
 const before=structuredClone([...s.assets]);result=await store.importTidalInventory(tidalResult.assets);
 assert.match(result.error,/CSV imports cannot verify/);assert.deepEqual([...s.assets],before);assert.equal(tidalReads,1);
});
test('reviewed Tidal refuses missing/unapproved row provenance and deleted destinations before applying any assets',async()=>{
 for(const scope of [undefined,'Wrong-Company','vendor-a']){
  const s=fixture();routes=[route('tidal',acme.id,'Vendor-A')];
  tidalResult={assets:[{...device,customer:'Acme',sourceCompanyId:'Vendor-A'},{...device,externalId:'bad',customer:'Acme',sourceCompanyId:scope}],errors:[]};
  assert.match((await store.importFromTidal()).error,/no inventory was applied/);unchanged(s);
 }
 const s=fixture();routes=[route('tidal',acme.id,'Vendor-A')];afterDevices=()=>s.companies.delete(acme.id);
 assert.match((await store.importFromTidal()).error,/no inventory was applied/);unchanged(s);
});
test('scoped automatic gap scan considers only imported customer assets',async()=>{
 const s=fixture();
 for(const c of [acme,beacon])s.assets.set(c.id,{...device,id:c.id,identifier:c.id+'.fixture.test',hostname:c.id+'.fixture.test',companyId:c.id,companyName:c.name,source:'manual'});
 assert.equal((await store.autoScanGaps(new Set())).gapsFound,0);assert.equal(s.folders.size,0);
 const result=await store.autoScanGaps(new Set([beacon.id]));assert.equal(result.companies,1);assert.equal(result.gapsFound,1);
 assert.ok([...s.folders.values()].every(f=>f.companyId===beacon.id));assert.ok([...s.scans.values()].every(f=>f.companyId===beacon.id));
});
test('reviewed CrowdStrike selects exact configuration and passes CID validation while retaining customer-scoped inventory',async()=>{
 const s=fixture([acme,company('CO-C',' ACME '),beacon]);
 configs=[{sourceRef:'environment:FALCON',label:'one',customerName:'Acme'},{sourceRef:'environment:FALCON_2',label:'two',customerName:'Other'}];
 routes=[{...route('crowdstrike',beacon.id,'a'.repeat(32)),connectionRef:'environment:FALCON'}];
 const result=await store.importFromCrowdstrike();assert.equal(result.assetsUpserted,1);assert.equal(result.skipped,1);assert.equal(crowdstrikeReads.length,1);
 assert.equal(crowdstrikeReads[0].config,configs[0]);assert.deepEqual(crowdstrikeReads[0].scope,{expectedCid:'a'.repeat(32)});
 assert.equal([...s.assets.values()][0].companyId,beacon.id);assert.equal(s.companies.size,3);
});
test('reviewed CrowdStrike never substitutes configuration, applies failed-CID results or recreates a deleted customer',async()=>{
 for(const scenario of ['absent','duplicate','cid','deleted']){
  const s=fixture();configs=[{sourceRef:scenario==='absent'?'environment:FALCON_2':'environment:FALCON',label:'one',customerName:'Acme'}];
  if(scenario==='duplicate')configs.push({...configs[0]});
  routes=[{...route('crowdstrike',acme.id,'a'.repeat(32)),connectionRef:'environment:FALCON'}];
  if(scenario==='cid')falconFailure='environment:FALCON';if(scenario==='deleted')afterDevices=()=>s.companies.delete(acme.id);
  assert.ok((await store.importFromCrowdstrike()).error);unchanged(s);
  if(['absent','duplicate'].includes(scenario))assert.equal(crowdstrikeReads.length,0);
 }
 const s=fixture();configs=[{sourceRef:'environment:FALCON',label:'one'},{sourceRef:'environment:FALCON_2',label:'two'}];
 routes=configs.map((c,i)=>({...route('crowdstrike',i?beacon.id:acme.id,(i?'b':'a').repeat(32)),connectionRef:c.sourceRef}));falconFailure='environment:FALCON';
 const result=await store.importFromCrowdstrike();assert.equal(result.assetsUpserted,1);assert.ok(result.tenants[0].error);assert.equal([...s.assets.values()][0].companyId,beacon.id);
});
test('reviewed Automate client ID wins over duplicate names; unassigned clients cannot create customers or overwrite other inventory',async()=>{
 const s=fixture([acme,company('CO-C',' ACME '),beacon]);
 routes=[route('automate',beacon.id,'17')];clients=[{id:'17',name:'Acme'},{id:'18',name:'New customer'}];
 s.assets.set('existing',{...device,id:'existing',identifier:device.hostname,companyId:acme.id,companyName:acme.name,source:'manual'});
 // If unassigned findings were rescored, this deliberately incomplete record would fail.
 const finding={id:'keep',companyId:acme.id,realRisk:73};s.findings.set('keep',finding);
 const before=structuredClone(s.assets.get('existing'));
 const result=await store.importFromAutomate();
 assert.equal(result.assetsUpserted,1);assert.equal(result.skipped,1);assert.equal(result.companiesCreated,0);
 assert.deepEqual(requestedClients,['17']);assert.equal(s.companies.size,3);assert.equal(s.assets.size,2);
 assert.deepEqual(s.assets.get('existing'),before);assert.deepEqual(finding,{id:'keep',companyId:acme.id,realRisk:73});
 assert.equal([...s.assets.values()].find(a=>a.id!=='existing').companyId,beacon.id);
});
test('reviewed inventory imports stop before vendor collection when approval is missing, stale, or customer is unavailable',async()=>{
 for(const provider of ['automate','intune','tidal','crowdstrike'])for(const scenario of ['empty','stale','missing']){
  const s=fixture();routes=scenario==='empty'?[]:[route(provider,'UNKNOWN',provider==='intune'?tenantId:'17')];routeError=scenario==='stale';
  configs=[{sourceRef:'environment:FALCON',label:'one'}];
  const result=await store[{intune:'importFromIntune',automate:'importFromAutomate',tidal:'importFromTidal',crowdstrike:'importFromCrowdstrike'}[provider]]();
  assert.ok(result.error);assert.equal(clientReads,0);assert.equal(deviceReads,0);assert.equal(intuneReads,0);assert.equal(tidalReads,0);assert.equal(crowdstrikeReads.length,0);unchanged(s);
 }
});
test('reviewed Automate detects duplicate/absent client IDs and deletion during collection without inventing ownership',async()=>{
 let s=fixture();routes=[route('automate',acme.id,'17')];clients=[{id:'17',name:'A'},{id:'17',name:'B'}];
 assert.match((await store.importFromAutomate()).error,/duplicate client/);assert.equal(deviceReads,0);unchanged(s);
 s=fixture();routes=[route('automate',acme.id,'17')];clients=[{id:'18',name:'Acme'}];
 let result=await store.importFromAutomate();assert.equal(result.errors.length,1);assert.equal(result.skipped,1);assert.equal(deviceReads,0);unchanged(s);
 s=fixture();routes=[route('automate',acme.id,'17')];clients=[{id:'17',name:'Other'}];afterDevices=()=>s.companies.delete(acme.id);
 result=await store.importFromAutomate();assert.equal(result.errors.length,1);assert.equal(result.assetsUpserted,0);unchanged(s);assert.equal(s.companies.has(acme.id),false);
});
test('reviewed Intune uses its exact tenant and customer, pins configuration and never falls back to internal',async()=>{
 let s=fixture([acme,beacon,company('CO-I','Internal','internal')]);routes=[route('intune',beacon.id,tenantId)];
 let result=await store.importFromIntune();assert.equal(result.assetsUpserted,1);assert.equal([...s.assets.values()][0].companyId,beacon.id);
 assert.equal(intuneConfigUsed.tenantId,tenantId);assert.equal(s.companies.size,3);
 for(const invalid of [[route('intune',acme.id,'wrong-tenant')],[route('intune',acme.id,tenantId),route('intune',beacon.id,tenantId)]]){
  s=fixture();routes=invalid;result=await store.importFromIntune();assert.ok(result.error);assert.equal(intuneReads,0);unchanged(s);
 }
 s=fixture();routes=[route('intune',acme.id,tenantId)];afterDevices=()=>s.companies.delete(acme.id);
 result=await store.importFromIntune();assert.match(result.error,/no longer available/);unchanged(s);assert.equal(s.companies.has(acme.id),false);
});
test('Intune and Falcon never choose between multiple internal or named customers; other Falcon tenants continue',async()=>{
 let s=fixture([company('CO-A','Internal East','internal'),company('CO-B','Internal West','internal')]);
 assert.match((await store.importFromIntune()).error,/Multiple internal/);unchanged(s);
 configs=[{label:'internal'}];assert.match((await store.importFromCrowdstrike()).error,/Multiple internal/);unchanged(s);
 s=fixture([acme,company('CO-C',' ACME '),beacon]);configs=[{label:'ambiguous',customerName:'Acme'},{label:'valid',customerName:'Beacon'}];
 const result=await store.importFromCrowdstrike();assert.equal(result.assetsUpserted,1);assert.match(result.tenants[0].error,/Multiple platform/);
 assert.equal([...s.assets.values()][0].companyId,beacon.id);
});
test('Nessus refuses ambiguous folder names and a scan moved to a different customer',async()=>{
 let s=fixture([acme,company('CO-C',' ACME ')]);folders=[{id:1,name:'Acme',type:'custom'}];scans=[{id:10,folderId:1,name:'scan',status:'completed',lastModified:10}];
 let result=await store.importFromNessus();assert.equal(result.companiesCreated,0);assert.equal(result.errors.length,1);unchanged(s);
 s=fixture();folders=[{id:1,name:'Acme',type:'custom'}];scans=[{id:10,folderId:1,name:'moved',status:'completed',lastModified:10}];
 const existing={id:'SCAN-OLD',companyId:beacon.id,vendor:{nessusScanId:10,nessusLastModified:5}};s.scans.set(existing.id,existing);
 result=await store.importFromNessus();assert.equal(result.scansImported,0);assert.equal(result.skipped,1);assert.match(result.errors[0],/different company/);
 assert.equal(s.scans.size,1);assert.equal(existing.vendor.nessusLastModified,5);assert.equal(s.findings.size,0);
});

test('approved consolidation customers cannot use the unsafe general merge or implicit Nessus name matching',async()=>{
 const source=company('CO-9150','GMI Scans','internal'),destination=company('CO-229336','Global Market Innovators, Inc.','internal');
 let s=fixture([source,destination]);
 assert.match(store.mergeCompanies(source.id,destination.id).error,/purpose-built consolidation/i);
 assert.match(store.mergeCompanies(destination.id,source.id).error,/purpose-built consolidation/i);
 assert.equal(s.companies.has(source.id),true);
 s=fixture([destination]);folders=[{id:9150,name:'GMI Scans',type:'custom'}];scans=[{id:20,folderId:9150,name:'legacy',status:'completed',lastModified:10}];
 const result=await store.importFromNessus();
 assert.equal(result.companiesCreated,0);assert.equal(s.companies.size,1);assert.equal(nessusReads.length,0);
 assert.match(result.errors[0],/reviewed folder route/i);
 s.meta.customerConsolidation={version:1,mappings:[{sourceId:source.id,destinationId:destination.id}]};
 assert.match(store.createCompany({name:'GMI Scans',allowNearDuplicate:true}).error,/historical customer name/i);
 folders=[{id:9150,name:'Renamed legacy folder',type:'custom'}];
 assert.match((await store.importFromNessus()).error,/reviewed numeric folder routes/i);
 assert.equal(s.companies.size,1);
});

test('unconsolidated Nessus folders keep their existing customer and import recurring results once',async()=>{
 for(const [id,name,parentId] of [['CO-9150','GMI Scans','CO-229336'],['CO-9153','Valor Global Scans','CO-229438']]){
  const s=fixture([company(id,name),company(parentId,'Parent')]);
  folders=[{id:11,name,type:'custom'}];scans=[{id:166,folderId:11,name:'Recurring scan',status:'completed',lastModified:20}];
  const old={id:'OLD',companyId:id,connector:'nessus',status:'Completed',completedAt:new Date(10000).toISOString(),vendor:{nessusScanId:166,nessusLastModified:10,imported:true}};
  s.scans.set(old.id,old);
  nessusResults={findings:Array.from({length:501},(_,i)=>({cve:`CVE-2026-${10000+i}`,cves:[`CVE-2026-${10000+i}`],asset:'host.example',assetAliases:['host.example'],title:'Finding',severity:'High',cvss:8,remediation:'Patch'})),scannedHosts:[{hostname:'host.example',assetAliases:['host.example']}]};
  const first=await store.importFromNessus();assert.equal(first.scansImported,1);assert.deepEqual(first.errors,[]);
  assert.equal(s.findings.size,501);assert.ok([...s.findings.values()].every(f=>f.companyId===id));assert.equal(s.companies.size,2);
  assert.equal(s.scans.get('OLD'),old);assert.equal(s.scans.size,2);
  assert.equal((await store.importFromNessus()).scansImported,0);assert.equal(nessusReads.length,1);assert.equal(s.scans.size,2);
 }
});

test('legacy Nessus exceptions cannot recreate, guess or cross customer ownership',async()=>{
 for(const kind of ['missing','wrong-id','duplicate','foreign-scan','consolidated']){
  const id='CO-9153',name='Valor Global Scans';
  const companies=[company('CO-229438','Valor Global, LLC')];
  if(kind!=='missing')companies.push(company(kind==='wrong-id'?'CO-OTHER':id,name));
  if(kind==='duplicate')companies.push(company('CO-DUP',name));
  const s=fixture(companies);folders=[{id:11,name,type:'custom'}];scans=[{id:166,folderId:11,name:'Scan',status:'completed',lastModified:20}];
  if(kind==='foreign-scan')s.scans.set('FOREIGN',{id:'FOREIGN',companyId:'CO-229438',vendor:{nessusScanId:166,imported:true,nessusLastModified:10}});
  if(kind==='consolidated')s.meta.customerConsolidation={version:1};
  const before=s.companies.size,result=await store.importFromNessus();
  assert.ok(result.error||result.errors.length);assert.equal(nessusReads.length,0);assert.equal(s.findings.size,0);assert.equal(s.companies.size,before);
 }
});

test('CrowdStrike inventory cannot overwrite canonical Automate metadata after consolidation',async()=>{
 const destination=company('CO-229336','Global Market Innovators, Inc.','internal');
 const s=fixture([destination]);
 const automate={...device,id:'AST-AUTO',companyId:destination.id,companyName:destination.name,identifier:device.hostname,source:'automate',externalId:'auto-1',os:'Automate OS'};
 s.assets.set(automate.id,automate);configs=[{label:'GMI',customerName:destination.name}];
 await store.importFromCrowdstrike();
 assert.equal(s.assets.get(automate.id).source,'automate');
 assert.equal(s.assets.get(automate.id).externalId,'auto-1');
 assert.equal(s.assets.get(automate.id).os,'Automate OS');
});

const spotlightRoute=()=>({companyId:acme.id,connectionRef:'environment:FALCON',sourceScope:'a'.repeat(32),bindingKey:'a'.repeat(64),candidateId:'b'.repeat(64),candidateHash:'c'.repeat(64),bindingRevision:1,revision:1});
test('actual Spotlight entrypoint selects explicit reviewed customer and rechecks approval before publication',async()=>{
 const s=fixture();configs=[{sourceRef:'environment:FALCON',customerName:'Beacon',label:'Fixture'}];spotlightRoutes=[spotlightRoute()];
 assert.equal((await store.importFromCrowdstrikeSpotlight()).findingsImported,1);assert.equal(spotlightRuns[0].companyId,acme.id);assert.equal(spotlightPromotions,1);unchanged(s);
 afterSpotlight=()=>{spotlightRoutes=[{...spotlightRoute(),bindingKey:'d'.repeat(64)}];};
 assert.match((await store.importFromCrowdstrikeSpotlight()).error,/approval changed/);assert.equal(spotlightPromotions,1);
});
test('actual Spotlight entrypoints cannot bypass missing/stale routes, deleted customers or ambiguity with a supplied selection',async()=>{
 for(const failure of ['empty','stale','deleted','wrong-ref','two']){
  fixture(failure==='deleted'?[beacon]:[acme,beacon]);configs=[{sourceRef:'environment:FALCON',customerName:'Acme',label:'Fixture'}];spotlightRoutes=[spotlightRoute()];
  if(failure==='empty')spotlightRoutes=[];if(failure==='stale')spotlightFailure=true;
  if(failure==='wrong-ref')spotlightRoutes[0].connectionRef='environment:FALCON_2';
  if(failure==='two')spotlightRoutes.push(spotlightRoute());
  assert.ok((await store.importFromCrowdstrikeSpotlight({config:configs[0],companyId:acme.id,tenantKey:acme.id})).error);
  assert.equal((await store.startCsSpotlightSync(acme.id)).started,false);assert.equal(spotlightRuns.length,0);assert.equal(spotlightPromotions,0);
 }
});
test('Spotlight switch off preserves the existing named-tenant selection',async()=>{
 fixture();configs=[{customerName:'Beacon',label:'Legacy'}];assert.equal((await store.importFromCrowdstrikeSpotlight()).findingsImported,1);
 assert.equal(spotlightRuns[0].companyId,beacon.id);assert.equal(spotlightRuns[0].reviewedScope,undefined);
});

const scannerRoute=()=>({provider:'nessus',companyId:acme.id,sourceScope:'17',connectionRef:'environment:scanner:nessus',candidateId:'a'.repeat(64),revision:1,bindingRevision:1,targets:['10.0.0.0/24']});
function scannerFixture(){const s=fixture();scannerRoutes=[scannerRoute()];folders=[{id:17,name:'Beacon',type:'custom'}];scans=[{id:10,folderId:17,name:'Fixture',status:'completed',lastModified:100}];
 nessusResults={scannedHosts:[{hostname:'host.example',assetAliases:['10.0.0.1']}],findings:[]};return s;}
test('reviewed Nessus uses folder ID instead of name and rechecks all data before publishing',async()=>{
 const s=scannerFixture();const result=await store.importFromNessus();assert.equal(result.scansImported,1);assert.equal([...s.scans.values()][0].companyId,acme.id);assert.equal(nessusReads[0].scope.folderId,17);assert.equal(s.companies.size,2);
 for(const failure of ['foreign-host','revoked','changed','deleted']){
  const next=scannerFixture();if(failure==='foreign-host')nessusResults.scannedHosts.push({hostname:'foreign',assetAliases:['10.1.0.1']});
  if(failure==='revoked')afterNessus=()=>{scannerRoutes=[];};if(failure==='changed')afterNessus=()=>{scannerRoutes=[{...scannerRoute(),revision:2}];};
  if(failure==='deleted')afterNessus=()=>{next.companies.delete(acme.id);};
  const rejected=await store.importFromNessus();assert.equal(rejected.scansImported,0);assert.ok(rejected.errors.length);assert.equal(next.findings.size,0);assert.equal(next.scans.size,0);
 }
});
test('reviewed Nessus rejects missing routing before API/state changes and supports approved native start/control',async()=>{
 let s=scannerFixture();scannerRoutes=[];assert.ok((await store.importFromNessus()).error);assert.equal(nessusReads.length,0);unchanged(s);
 s=scannerFixture();const input={name:'Fixture',connector:'nessus',profile:'standard',companyId:acme.id,targets:['10.0.1.1']};
 assert.ok((await store.startScan(input)).error);assert.equal(nessusLaunches.length,0);
 const scan=await store.startScan({...input,targets:['10.0.0.1']});assert.equal(nessusLaunches[0].scope.folderId,17);
 await store.scanAction(scan.id,'pause');assert.equal(nessusControls.length,1);
 scans=[];assert.ok((await store.scanAction(scan.id,'resume')).error);assert.equal(nessusControls.length,1);
 scannerRoutes=[];assert.ok((await store.scanAction(scan.id,'rescan')).error);assert.equal(nessusLaunches.length,1);
});

test('reviewed Nessus clean-host reconciliation changes only the approved customer after full validation',async()=>{
 const s=scannerFixture();const old={id:'old',companyId:acme.id,companyName:acme.name,scanId:'prior',connector:'nessus',status:'Open',asset:'10.0.0.1',cve:'CVE-2026-1234',severity:'High',cvss:8,lastSeen:'2026-01-01'};
 s.findings.set('old',old);s.findings.set('other',{...old,id:'other',companyId:beacon.id});
 s.scans.set('prior',{id:'prior',companyId:acme.id,connector:'nessus',completedAt:new Date(50000).toISOString(),vendor:{nessusScanId:10,nessusLastModified:50,imported:true}});
 assert.equal((await store.importFromNessus()).errors.length,0);assert.equal(old.status,'Resolved');assert.equal(s.findings.get('other').status,'Open');
 const next=scannerFixture();next.findings.set('old',{...old,status:'Open'});nessusResults.scannedHosts.push({hostname:'foreign',assetAliases:['10.1.0.1']});
 assert.ok((await store.importFromNessus()).errors.length);assert.equal(next.findings.get('old').status,'Open');assert.equal(next.scans.size,0);
});

test('reviewed scan polling shares route/roster reads and blocks moved scans before status or findings calls',async()=>{
 const s=scannerFixture();await store.listScans();assert.equal(scannerRouteLoads,0);
 nessusStatus='running';scans.push({...scans[0],id:11});
 for(const id of [10,11])s.scans.set('scan-'+id,{id:'scan-'+id,name:'Fixture',companyId:acme.id,companyName:acme.name,connector:'nessus',targets:['10.0.0.1'],status:'Queued',createdAt:'2026-01-01',startedAt:'2026-01-01',vendor:{nessusScanId:id,lastPoll:0,imported:false},severityCounts:{},findingsCount:0,hostsScanned:0});
 await store.listScans();assert.equal(scannerRouteLoads,1);assert.equal(nessusRosterReads,1);assert.equal(nessusStatusReads,2);assert.equal(nessusReads.length,0);
 scans=[];for(const scan of s.scans.values())scan.vendor.lastPoll=0;
 await store.listScans();assert.equal(nessusStatusReads,2);assert.ok([...s.scans.values()].every(scan=>/no longer/.test(scan.error)));
});

test('reviewed Nessus repeated sync reuses a pending scan and imports each completed run once',async()=>{
 const s=scannerFixture();scans[0].status='running';
 assert.equal((await store.importFromNessus()).scansImported,1);const pending=[...s.scans.values()][0];
 assert.equal((await store.importFromNessus()).scansImported,0);assert.equal(s.scans.size,1);assert.equal(nessusReads.length,0);
 scans[0].status='completed';scans[0].lastModified=200;
 assert.equal((await store.importFromNessus()).errors.length,0);assert.equal(s.scans.size,1);assert.equal(pending.vendor.imported,true);assert.equal(pending.status,'Completed');assert.equal(nessusReads.length,1);
 assert.equal((await store.importFromNessus()).scansImported,0);assert.equal(nessusReads.length,1);
 scans[0].lastModified=300;assert.equal((await store.importFromNessus()).scansImported,1);assert.equal(s.scans.size,2);assert.equal(nessusReads.length,2);
 assert.equal((await store.importFromNessus()).scansImported,0);assert.equal(s.scans.size,2);assert.equal(nessusReads.length,2);
});

const osintRoute=(provider,companyId=acme.id)=>({...scannerRoute(),provider,companyId,sourceScope:provider==='artemis'?'ExactTag':'targets:fixture',connectionRef:'environment:scanner:'+provider,targets:['acme.example']});
test('reviewed SpiderFoot routes by exact approved root, preserves existing scan ownership and ignores misleading names',async()=>{
 const s=fixture();osintRoutes.spiderfoot=[osintRoute('spiderfoot')];sfScans=[{id:'sf-1',name:'Beacon',target:'ACME.example.',status:'FINISHED'}];sfFindings=[{...arItem('unused','third-party.example'),module:'fixture'}];
 assert.equal((await store.importFromSpiderfoot()).findingsImported,1);assert.equal([...s.findings.values()][0].companyId,acme.id);assert.equal(sfScopes[0].scan.id,'sf-1');
 assert.equal((await store.importFromSpiderfoot()).scansImported,0);assert.equal(sfReads,1);
 osintRoutes.spiderfoot=[osintRoute('spiderfoot',beacon.id)];assert.match((await store.importFromSpiderfoot()).skipped[0].reason,/different company/);assert.equal(sfReads,1);
 sfScans=[{id:'sf-2',name:'Acme',target:'other.acme.example',status:'FINISHED'}];assert.equal((await store.importFromSpiderfoot()).scansImported,0);assert.equal(sfReads,1);
});
test('OSINT imports fail closed on missing, revoked or changed assignments without moving or applying findings',async()=>{
 for(const provider of ['spiderfoot','artemis'])for(const failure of ['empty','error','revoked','revision','deleted']){
  const s=fixture();osintRoutes[provider]=failure==='empty'?[]:[osintRoute(provider)];osintError=failure==='error';
  sfScans=[{id:'sf-1',name:'Acme',target:'acme.example',status:'FINISHED'}];sfFindings=[arItem('unused')];arFindings=[arItem('ExactTag')];
  afterOsint=()=>{if(failure==='revoked')osintRoutes[provider]=[];if(failure==='revision')osintRoutes[provider][0]={...osintRoutes[provider][0],revision:2};if(failure==='deleted')s.companies.delete(acme.id);};
  const result=await store[provider==='spiderfoot'?'importFromSpiderfoot':'importFromArtemis']();
  assert.ok(result.error||result.skipped.length);unchanged(s);if(['empty','error'].includes(failure))assert.equal(sfReads+arReads.length,0);
 }
});
test('reviewed Artemis uses its exact tag owner and never reassigns an existing tag scan',async()=>{
 const s=fixture();osintRoutes.artemis=[osintRoute('artemis',beacon.id)];arFindings=[arItem('ExactTag','third-party.example'),arItem('other')];
 assert.equal((await store.importFromArtemis()).findingsImported,1);assert.equal([...s.findings.values()][0].companyId,beacon.id);assert.equal(arReads[0].tag,'ExactTag');
 assert.deepEqual(arReads[0].targets,['acme.example']);assert.equal(s.scans.size,1);
 osintRoutes.artemis=[osintRoute('artemis')];assert.match((await store.importFromArtemis()).skipped[0].reason,/different company/);assert.equal(s.findings.size,1);
});
test('reviewed OSINT preview and launch use approved roots/tags only; per-target revocation stops further launches',async()=>{
 fixture();osintRoutes={spiderfoot:[osintRoute('spiderfoot')],artemis:[osintRoute('artemis',beacon.id)]};
 const preview=await store.previewOsintTargets();assert.equal(preview.companies,2);assert.equal(preview.domainsTotal,2);assert.equal(osintLaunches.length,0);
 const result=await store.launchOsintScans();assert.equal(result.spiderfoot.launched,1);assert.equal(result.artemis.launched,1);assert.equal(osintLaunches.find(c=>c.provider==='artemis').tag,'ExactTag');assert.ok(osintLaunches.every(c=>c.scope));
 fixture();osintRoutes={spiderfoot:[{...osintRoute('spiderfoot'),targets:['acme.example','second.example']}],artemis:[osintRoute('artemis',beacon.id)]};
 afterOsint=()=>{osintRoutes.spiderfoot=[];};const revoked=await store.launchOsintScans();assert.equal(revoked.spiderfoot.launched,1);assert.equal(revoked.spiderfoot.failed,1);
 osintError=true;await assert.rejects(()=>store.previewOsintTargets());const count=osintLaunches.length;assert.ok((await store.launchOsintScans()).errors.length);assert.equal(osintLaunches.length,count);
});
test('reviewed OSINT cannot auto-pivot related hosts without separate Nessus approval',async()=>{
 const s=fixture();s.settings.autoScanNewAssets=true;osintRoutes.spiderfoot=[osintRoute('spiderfoot')];sfScans=[{id:'sf-1',name:'Acme',target:'acme.example',status:'FINISHED'}];sfFindings=[{...arItem('unused','third-party.example'),category:'SpiderFoot: TCP_PORT_OPEN'}];
 assert.equal((await store.importFromSpiderfoot()).findingsImported,1);assert.equal(nessusLaunches.length,0);assert.equal(s.scans.size,1);
});

test('reviewed Artemis explicitly reports pending analyses while retaining existing and completed observations',async()=>{
 const s=fixture();osintRoutes.artemis=[osintRoute('artemis')];arFindings=[arItem('ExactTag')];arIncomplete=2;
 const old={id:'old',companyId:acme.id,connector:'artemis',status:'Open',cve:'OLD',asset:'previous.example',title:'Previous'};s.findings.set('old',old);
 const result=await store.importFromArtemis();assert.equal(result.findingsImported,1);assert.match(result.skipped[0].reason,/2 pending or stopped/);assert.equal(old.status,'Open');assert.equal(s.findings.size,2);
});

const activeRoute=provider=>({...scannerRoute(),provider,sourceScope:'targets:fixture',connectionRef:'environment:scanner:'+provider,targets:[provider==='zap'?'https://app.example':'10.0.0.1']});
const activeInput=provider=>({companyId:acme.id,connector:provider,profile:'standard',name:'Active fixture',targets:activeRoute(provider).targets});
async function settleActive(s,id){for(let i=0;i<100;i++){if(s.scans.get(id)?.completedAt)return s.scans.get(id);await new Promise(r=>setImmediate(r));}assert.fail('Fixture worker did not settle');}
for(const provider of ['zap','vulners']){
 test(`${provider}: reviewed scope blocks unauthorized launches before local or remote changes`,async()=>{
  for(const mode of ['none','other','invalid']){
   const s=fixture();activeRoutes[provider]=mode==='none'?[]:[activeRoute(provider)];
   const input=activeInput(provider);if(mode==='other')input.companyId=beacon.id;if(mode==='invalid')input.targets=[provider==='zap'?'https://app.example.evil':'10.0.0.2'];
   assert.ok((await store.startScan(input)).error);assert.equal(activeLaunches.length,0);unchanged(s);assert.equal(s.folders.size,0);
  }
 });
 test(`${provider}: native job completes for approved customer, keeps prior evidence and rechecks before publication`,async()=>{
  for(const mode of ['success','revoked','changed-config','failed']){
   const s=fixture();activeRoutes[provider]=[activeRoute(provider)];
   const target=activeInput(provider).targets[0];
   activeResults=[{cve:'CVE-2026-1234',cvss:8,component:'Service',target,asset:target,severity:'High',title:'Fixture',description:'Fixture',remediation:'Patch',category:'Test'}];
   if(mode==='revoked')afterActive=()=>{activeRoutes[provider]=[];};
   if(mode==='changed-config')afterActive=()=>{activeConfig={...activeConfig,baseUrl:'https://changed.invalid'};};
   if(mode==='failed')activeFail=true;
   s.findings.set('prior',{id:'prior',companyId:acme.id,connector:provider,cve:'CVE-2026-9999',asset:target,status:'Open',severity:'High',cvss:8});
   const scan=await store.startScan(activeInput(provider));assert.ok(scan.id);const done=await settleActive(s,scan.id);
   assert.equal(done.status,mode==='success'?'Completed':'Failed');assert.equal(done.hostsScanned,mode==='success'?1:0);
   assert.equal(s.findings.size,mode==='success'?2:1);assert.equal(s.findings.get('prior').status,'Open');
   if(mode==='success')assert.equal([...s.findings.values()].find(f=>f.id!=='prior').companyId,acme.id);
  }
 });
 test(`${provider}: real jobs reject simulated controls; rescan launches a fresh checked job`,async()=>{
  const s=fixture();activeRoutes[provider]=[activeRoute(provider)];const first=await store.startScan(activeInput(provider));
  for(const action of ['pause','resume','stop'])assert.ok((await store.scanAction(first.id,action)).error);
  await settleActive(s,first.id);const second=await store.scanAction(first.id,'rescan');assert.notEqual(second.id,first.id);await settleActive(s,second.id);assert.equal(activeLaunches.length,2);
  activeRoutes[provider]=[];assert.ok((await store.scanAction(second.id,'rescan')).error);assert.equal(activeLaunches.length,2);
 });
}
test('bridge inventory sweep uses approved customer ownership and never closes prior findings without completeness evidence',async()=>{
 const s=fixture();activeRoutes.vulners=[activeRoute('vulners')];
 for(const c of [acme,beacon])s.assets.set(c.id,{...device,id:c.id,identifier:c.id,hostname:c.id,ipAddresses:['10.0.0.1'],companyId:c.id,companyName:c.name,source:'manual'});
 s.findings.set('prior',{id:'prior',companyId:acme.id,connector:'vulners',cve:'CVE-2026-9999',asset:'10.0.0.1',status:'Open',severity:'High',cvss:8});
 const result=await store.importFromVulnersBridge();assert.equal(result.hostsScanned,1);assert.equal(activeLaunches.length,1);assert.equal(result.skipped,1);assert.equal(s.findings.get('prior').status,'Open');
 activeRoutes.vulners=[];assert.ok((await store.importFromVulnersBridge()).error);assert.equal(activeLaunches.length,1);
});

test('ZAP polling exhaustion is failed coverage and never starts an active scan or publishes a report',async()=>{
 const s=fixture();activeRoutes.zap=[activeRoute('zap')];activeStatus=99;
 const original=globalThis.setTimeout;globalThis.setTimeout=(fn,ms,...args)=>original(fn,ms===5000?0:ms,...args);
 try{const scan=await store.startScan(activeInput('zap'));
  for(let i=0;i<150&&!s.scans.get(scan.id)?.completedAt;i++)await new Promise(r=>original(r,2));
  const done=s.scans.get(scan.id);assert.equal(done.status,'Failed');assert.equal(done.hostsScanned,0);assert.equal(done.zapScan.activeScanId,undefined);assert.equal(s.findings.size,0);
 }finally{globalThis.setTimeout=original;}
});
