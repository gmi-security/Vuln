import assert from 'node:assert/strict';
import test from 'node:test';
import {mutationHarness,seed,finding} from './connector-mutation-harness.mjs';
const date=day=>`2026-10-${day}T12:00:00.000Z`;
const source=(id,day,imported=true)=>({id:`S-${id}-${day}`,companyId:'CO-A',companyName:'Alpha',connector:'nessus',status:'Completed',completedAt:date(day),targets:[],vendor:{nessusScanId:id,nessusLastModified:Date.parse(date(day))/1000,imported,nessusEvidenceVersion:1}});
const item=()=>({...finding(),cves:['CVE-2026-12345'],assetAliases:['host-1']});
const result=(positive,covered=true)=>({findings:positive?[item()]:[],scannedHosts:covered?[{hostname:'host-1',assetAliases:['host-1']}]:[]});
const providers={'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async()=>null},'lib/nessus.ts':{nessusConfig:()=>null}};
async function harness(){const d=seed(),old=source(156,'20');d.scans=[[old.id,old],['S-14-19',source(14,'19')]];d.findings=[['F-1',{...finding(),scanId:old.id,lastSeen:date('20')}],['F-foreign',finding('F-foreign','CO-B')]];return mutationHarness({disk:{value:d},providers});}
async function apply(h,id,day,positive,covered=true){const scan=source(id,day,false);delete scan.vendor.nessusEvidenceVersion;h.memory().scans.set(scan.id,scan);h.store.markDirty({scans:[scan.id]});await h.store.importVendorFindings(h.memory(),scan,result(positive,covered));scan.vendor.imported=true;h.store.markDirty({scans:[scan.id]});await h.flush();h.assertPersisted();return scan;}
test('discovery cannot close another policy; both corroborating sources must clear before resolution',async()=>{
 const h=await harness();await apply(h,166,'21',false);assert.equal(h.memory().findings.get('F-1').status,'Open');
 await apply(h,14,'21',true);await apply(h,156,'22',false);assert.equal(h.memory().findings.get('F-1').status,'Open');
 await apply(h,14,'22',false);assert.equal(h.memory().findings.get('F-1').status,'Resolved');assert.equal(h.memory().findings.get('F-foreign').status,'Open');
 const restarted=await mutationHarness({disk:h.disk,providers});assert.equal(restarted.memory().findings.get('F-1').nessusObservations['14'].present,false);
});
test('older source results cannot close or reopen a newer observation; older other-source positives preserve lastSeen',async()=>{
 const h=await harness();await assert.rejects(()=>apply(h,156,'19',false),/older/i);assert.equal(h.memory().findings.get('F-1').status,'Open');
 await apply(h,14,'19',true);assert.equal(h.memory().findings.get('F-1').lastSeen,date('20'));
 await apply(h,156,'21',false);await apply(h,14,'21',false);assert.equal(h.memory().findings.get('F-1').status,'Resolved');
 await assert.rejects(()=>apply(h,14,'20',true),/older/i);assert.equal([...h.memory().findings.values()].filter(f=>f.companyId==='CO-A'&&f.status==='Open').length,0);
});
test('uncovered hosts, incomplete baseline and other connector evidence remain open',async()=>{
 const h=await harness();await apply(h,156,'21',false,false);assert.equal(h.memory().findings.get('F-1').status,'Open');
 delete h.memory().scans.get('S-14-19').vendor.nessusEvidenceVersion;
 h.store.markDirty({scans:['S-14-19']});
 await apply(h,156,'22',false);assert.equal(h.memory().findings.get('F-1').status,'Open');
 await apply(h,14,'22',true);h.memory().findings.get('F-1').seenBy=['nessus','vulners'];h.store.markDirty({findings:['F-1']});
 await apply(h,14,'23',false);assert.equal(h.memory().findings.get('F-1').status,'Open');
});

test('baseline replay survives a failed source and restart without prematurely closing findings or duplicating scans',async()=>{
 const d=seed(),first=source(156,'20'),second=source(14,'19');delete first.vendor.nessusEvidenceVersion;delete second.vendor.nessusEvidenceVersion;
 d.scans=[[first.id,first],[second.id,second]];d.findings=[['F-1',{...finding(),scanId:first.id,lastSeen:date('20')}]];
 let fail=true;const reads=[];
 const p={'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async()=>null},'lib/nessus.ts':{
  nessusConfig:()=>({url:'https://fixture.invalid'}),nessusListFolders:async()=>[{id:7,name:'Alpha',type:'custom'}],
  nessusListScans:async()=>[first,second].map(s=>({id:s.vendor.nessusScanId,folderId:7,name:'Scan',status:'completed',lastModified:s.vendor.nessusLastModified})),
  nessusImportFindings:async id=>{reads.push(id);if(id===14&&fail)throw Error('Nessus unavailable');return result(id===14);},
 }};
 let h=await mutationHarness({disk:{value:d},providers:p});const partial=await h.store.importFromNessus();h.assertPersisted();
 assert.equal(partial.errors.length,1);assert.equal(h.memory().findings.get('F-1').status,'Open');assert.equal(h.memory().scans.get(second.id).vendor.nessusEvidenceVersion,undefined);
 fail=false;h=await mutationHarness({disk:h.disk,providers:p});assert.equal((await h.store.importFromNessus()).errors.length,0);h.assertPersisted();
 assert.equal(h.memory().findings.get('F-1').status,'Open');assert.equal(h.memory().scans.size,2);assert.deepEqual(reads,[156,14,14]);
 await h.store.importFromNessus();assert.deepEqual(reads,[156,14,14]);
});

test('active Nessus corroboration survives a bridge clean result and is cleared only by its own scan',async()=>{
 const h=await harness(),f=h.memory().findings.get('F-1');f.connector='vulners';h.store.markDirty({findings:[f.id]});
 await apply(h,156,'21',true);assert.deepEqual(Object.keys(f.nessusObservations),['156']);
 const covered=new Set([h.store.canonicalAssetKey(h.memory(),'CO-A','host-1')]);
 assert.equal(await h.store.closeStaleFindings(h.memory(),'CO-A','vulners',covered,new Set(),date('22')),0);
 await apply(h,156,'22',false);assert.equal(f.nessusObservations['156'].present,false);
 assert.equal(await h.store.closeStaleFindings(h.memory(),'CO-A','vulners',covered,new Set(),date('23')),1);
 await h.flush();h.assertPersisted();
});

test('unknown historical origin stays open and concurrent collection of one source is refused',async()=>{
 const h=await harness();h.memory().findings.get('F-1').scanId='missing';h.store.markDirty({findings:['F-1']});
 await apply(h,156,'21',false);assert.equal(h.memory().findings.get('F-1').status,'Open');
 let release;const held=new Promise(resolve=>{release=resolve;});
 const p={...providers,'lib/nessus.ts':{nessusConfig:()=>({url:'https://fixture.invalid'}),nessusImportFindings:async()=>{await held;return result(true);}}};
 const g=await mutationHarness({providers:p}),scan=source(156,'21',false);g.memory().scans.set(scan.id,scan);g.store.markDirty({scans:[scan.id]});
 const first=g.store.importVendorFindings(g.memory(),scan);
 await assert.rejects(()=>g.store.importVendorFindings(g.memory(),scan),/already being imported/);release();await first;await g.flush();g.assertPersisted();
});


test('all aliases are linked before correlating reported findings',async()=>{
 const h=await harness(),scan=source(156,'21',false);
 const data={findings:[{...item(),asset:'10.0.0.1',assetAliases:['10.0.0.1']},{...item(),cve:'CVE-2026-99999',asset:'server.example',assetAliases:['server.example','10.0.0.1','host-1']}],scannedHosts:[{hostname:'server.example',assetAliases:['10.0.0.1','host-1']}]};
 h.memory().scans.set(scan.id,scan);h.store.markDirty({scans:[scan.id]});await h.store.importVendorFindings(h.memory(),scan,data);
 const own=[...h.memory().findings.values()].filter(f=>f.companyId==='CO-A');assert.equal(own.length,2);assert.ok(own.every(f=>f.status==='Open'&&f.nessusObservations['156'].present));
 await h.flush();h.assertPersisted();
});

test('missing vendor timestamps cannot downgrade a completed source or reopen its resolved findings',async()=>{
 const h=await harness();delete h.memory().scans.get('S-156-20').vendor.nessusLastModified;h.store.markDirty({scans:['S-156-20']});
 await assert.rejects(()=>apply(h,156,'19',false),/older/i);
 await apply(h,156,'21',false);delete h.memory().scans.get('S-156-21').vendor.nessusLastModified;h.store.markDirty({scans:['S-156-21']});
 await assert.rejects(()=>apply(h,156,'20',true),/older/i);assert.equal(h.memory().findings.get('F-1').status,'Resolved');
});

test('verified duplicate history wins a same-timestamp baseline tie',async()=>{
 const h=await harness(),duplicate={...source(14,'19'),id:'duplicate'};delete duplicate.vendor.nessusEvidenceVersion;
 h.memory().scans.set(duplicate.id,duplicate);h.store.markDirty({scans:[duplicate.id]});
 await apply(h,156,'21',false);assert.equal(h.memory().findings.get('F-1').status,'Resolved');
});

test('concurrent import entrypoints do not advance metadata for a skipped source',async()=>{
 const d=seed(),scan=source(156,'20',false);delete scan.vendor.nessusEvidenceVersion;d.scans=[[scan.id,scan]];
 let release,started;const held=new Promise(resolve=>release=resolve),entered=new Promise(resolve=>started=resolve);let day='20';
 const p={'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async()=>null},'lib/nessus.ts':{
  nessusConfig:()=>({url:'https://fixture.invalid'}),nessusListFolders:async()=>[{id:7,name:'Alpha',type:'custom'}],
  nessusListScans:async()=>[{id:156,folderId:7,name:'Scan',status:'completed',lastModified:Date.parse(date(day))/1000}],
  nessusImportFindings:async()=>{started();await held;return result(true);},
 }};
 const h=await mutationHarness({disk:{value:d},providers:p});const first=h.store.importFromNessus();await entered;day='21';
 const second=await h.store.importFromNessus();assert.equal(second.skipped,1);assert.equal(h.memory().scans.get(scan.id).completedAt,date('20'));
 release();await first;assert.equal(h.memory().scans.get(scan.id).vendor.nessusLastModified,Date.parse(date('20'))/1000);h.assertPersisted();
});
