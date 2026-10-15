import assert from 'node:assert/strict';
import test from 'node:test';
import {mutationHarness,seed,asset,finding,clone} from './connector-mutation-harness.mjs';
const now='2026-10-15T12:00:00.000Z';
const item={cve:'CVE-2026-12345',asset:'alpha.example',title:'Patch fixture',severity:'High',cvss:8,category:'Network',description:'Evidence',remediation:'Update',port:'443',path:'/app',confidence:'Certain',tag:'Alpha'};
function data(){const d=seed();d.assets=[['A-1',{...asset(),identifier:'alpha.example',hostname:'alpha.example'}],['A-2',{...asset('A-2','CO-B'),identifier:'beta.example',hostname:'beta.example',ipAddresses:['10.0.0.2']}]];d.findings=[['foreign',{...finding('foreign','CO-B'),asset:'beta.example'}]];return d;}
function fixtures(mode,failed=false){
 const issue=()=>{if(failed)throw Error('Provider failed');return [clone(item)];};
 const providers={
  'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async()=>null},
  'lib/spiderfoot.ts':{isGarbageAssetIdentifier:()=>false,spiderfootConfig:()=>({url:'https://fixture.invalid'}),spiderfootListScans:async()=>[{id:'scan-1',name:'Alpha',target:'alpha.example',status:'FINISHED'}],spiderfootImportFindings:async()=>issue()},
  'lib/artemis.ts':{artemisConfig:()=>({url:'https://fixture.invalid'}),artemisImportFindings:async()=>issue()},
  'lib/burp.ts':{burpConfig:()=>({}),burpListIssues:async()=>issue()},
  'lib/vulners.ts':{vulnersConfig:()=>({}),vulnersEnrichCves:async()=>{issue();return new Map([[item.cve,{cvss:9.8,epss:.8,exploitAvailable:true,description:'Enriched'}]]);},vulnersBridgeConfig:()=>({url:'https://fixture.invalid'}),vulnersBridgeStartScan:async target=>{if(failed||target==='10.0.0.2')throw Error('Provider failed');return {jobId:target,status:'complete'};},vulnersBridgeJobFindings:async()=>[{cve:item.cve,cvss:8,component:'Port 443 HTTPS',exploitAvailable:false}]},
 };
 return providers;
}
const methods={spiderfoot:'importFromSpiderfoot',artemis:'importFromArtemis',burp:'importFromBurp',vulners:'importFromVulners',bridge:'importFromVulnersBridge'};
for(const mode of Object.keys(methods))test(`${mode} import and repeat preserve complete records through scoped save and restart`,async()=>{
 const run=async baseline=>{const h=await mutationHarness({disk:{value:data()},providers:fixtures(mode),now,baseline});
  await h.store[methods[mode]]();await h.flush();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);return h;};
 const h=await run(false);
 // Use a full-save comparison without the scoped assertion.
 const oracle=await mutationHarness({disk:{value:data()},providers:fixtures(mode),now,baseline:true});await oracle.store[methods[mode]]();await oracle.flush();oracle.assertPersisted();assert.deepEqual(h.disk.value,oracle.disk.value);
 const restarted=await mutationHarness({disk:h.disk,providers:fixtures(mode),now:'2026-10-16T12:00:00.000Z'});const count=h.disk.value.findings.length;
 await restarted.store[methods[mode]]();await restarted.flush();restarted.assertPersisted();assert.equal(restarted.disk.value.findings.length,count);
 if(mode==='vulners')assert.equal(new Map(restarted.disk.value.findings).get('foreign').epss,.8,'shared CVEs enrich every customer');
 else assert.deepEqual(new Map(restarted.disk.value.findings).get('foreign'),new Map(data().findings).get('foreign'));
});
for(const mode of Object.keys(methods))test(`${mode} provider failure retains previous completed data`,async()=>{
 const d=data(),h=await mutationHarness({disk:{value:clone(d)},providers:fixtures(mode,true),now});await h.store[methods[mode]]();await h.flush();h.assertPersisted();assert.deepEqual(h.disk.value.findings,d.findings);assert.deepEqual(h.disk.value.assets,d.assets);
});
test('Nmap upload saves port evidence and repeated findings without unrelated customer writes',async()=>{
 const host={host:'alpha.example',ip:'10.0.0.1',os:'Linux',ports:[{port:3389,protocol:'tcp',service:'rdp',product:'',version:''}]};
 const h=await mutationHarness({disk:{value:data()},now});h.store.importNmapScan([host]);await h.flush();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);assert.deepEqual(h.lastScope().assets,['A-1']);assert.equal(h.disk.value.findings.length,2,h.logs.join('\n'));
 const restarted=await mutationHarness({disk:h.disk,now:'2026-10-16T12:00:00.000Z'});restarted.store.importNmapScan([host]);await restarted.flush();restarted.assertPersisted();assert.equal(restarted.disk.value.findings.length,2);assert.equal(new Map(restarted.disk.value.assets).get('A-1').openPorts[0].port,3389);
});
for(const mode of ['zap','bridge'])for(const failed of [false,true])test(`${mode} asynchronous ${failed?'partial failure':'success'} persists progress and final status after earlier saves`,async()=>{
 const d=data();d.scans=[['S-1',{id:'S-1',name:'Active',companyId:'CO-A',companyName:'Alpha',connector:mode==='zap'?'zap':'vulners',status:'Running',targets:['https://alpha.example','https://bad.example'],findingsCount:0,severityCounts:{Critical:0,High:0,Medium:0,Low:0,Info:0},...(mode==='zap'?{zapScan:{phase:'spidering'}}:{bridgeScan:{done:false}})}]];
 let h;const checkpoint=async()=>{await h.flush();h.assertPersisted();};
 const providers=fixtures(mode);
 providers['lib/zap.ts']={zapConfig:()=>({}),zapStartSpider:async target=>{await checkpoint();if(failed&&target.includes('bad'))throw Error('Provider failed');return 'spider';},zapSpiderStatus:async()=>{await checkpoint();return 100;},zapStartActiveScan:async()=>{await checkpoint();return 'active';},zapActiveScanStatus:async()=>{await checkpoint();return 100;},zapFetchReport:async()=>{await checkpoint();return [{...item,asset:'https://alpha.example'}];}};
 providers['lib/vulners.ts'].vulnersBridgeStartScan=async target=>{await checkpoint();if(failed&&target.includes('bad'))throw Error('Provider failed');return {jobId:target,status:'complete'};};
 h=await mutationHarness({disk:{value:d},providers,now});const targets=failed?['https://alpha.example','https://bad.example']:['https://alpha.example'];
 await h.store[mode==='zap'?'runZapScanAsync':'runVulnersBridgeScanAsync']('S-1',targets,'CO-A');await h.flush();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);
 assert.equal(h.disk.value.scans[0][1].status,failed?'Failed':'Completed',h.logs.join('\n'));assert.equal(h.disk.value.findings.length,2,h.logs.join('\n'));
 const restarted=await mutationHarness({disk:h.disk,providers,now});restarted.assertPersisted();assert.equal(restarted.memory().scans.get('S-1').status,failed?'Failed':'Completed');
});
for(const empty of [false,true])test(`threat enrichment persists KEV metadata and ${empty?'an empty customer store':'every affected customer'}`,async()=>{
 const d=data();if(!empty)d.findings.push(['alpha',{...finding('alpha'),asset:'alpha.example'}]);else d.findings=[];
 const transport=async raw=>{
  const url=new URL(raw);
  if(url.hostname==='www.cisa.gov')return Response.json({vulnerabilities:[{cveID:item.cve,knownRansomwareCampaignUse:'Known'}]});
  if(url.hostname==='api.first.org')return Response.json({data:[{cve:item.cve,epss:'0.65'}]});
  throw Error('Unexpected enrichment transport');
 };
 const h=await mutationHarness({disk:{value:d},now,fetch:transport});await h.store.enrichThreatIntel();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);assert.ok(h.saves.length);
 if(!empty){assert.deepEqual(h.lastScope().findings,['foreign','alpha']);for(const[,f]of h.disk.value.findings){assert.equal(f.epss,.65);assert.equal(f.kev,true);}}
 const restarted=await mutationHarness({disk:h.disk,now,fetch:transport});restarted.assertPersisted();
});
for(const mode of ['burp','nmap'])test(`${mode} upload partial application retains the records already touched`,async()=>{
 const h=await mutationHarness({disk:{value:data()},now});let broken;
 if(mode==='burp'){broken={...item};Object.defineProperty(broken,'asset',{get(){throw Error('Malformed upload row');}});assert.throws(()=>h.store.importBurpFindings([item,broken]));}
 else {const host={host:'alpha.example',ip:'10.0.0.1',os:'Linux',ports:[{port:3389,protocol:'tcp',service:'rdp'}]};broken={...host};Object.defineProperty(broken,'host',{get(){throw Error('Malformed upload row');}});assert.throws(()=>h.store.importNmapScan([host,broken]));}
 await h.flush();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);assert.equal(h.disk.value.findings.length,2);
});
