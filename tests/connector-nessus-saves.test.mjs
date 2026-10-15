import assert from 'node:assert/strict';
import test from 'node:test';
import {mutationHarness,seed,finding,clone} from './connector-mutation-harness.mjs';
const now='2026-10-15T12:00:00Z',lastModified=Date.parse(now)/1000;
const item=(cve='CVE-2026-12345')=>({cve,cves:[cve],title:'Patch fixture',asset:'host-1',assetAliases:['host-1','10.0.0.1'],severity:'High',cvss:8,cvssV3:8,cvssV2:7,vpr:6,exploitAvailable:false,remediation:'Install update',description:'Evidence'});
const result=()=>({findings:[item(),item(),item('CVE-2026-99999')],scannedHosts:[{hostname:'host-1',assetAliases:['10.0.0.1']}]});
const scan=()=>({id:'S-1',name:'Scan',companyId:'CO-A',companyName:'Alpha',connector:'nessus',status:'Running',targets:['host-1'],vendor:{nessusScanId:9,lastPoll:0,imported:false},completedAt:null,findingsCount:0});
function providers(get=result){return {
 'lib/customer-scanner-routing-server.ts':{loadReviewedScannerRoutes:async()=>null},
 'lib/nessus.ts':{nessusConfig:()=>({url:'https://fixture.invalid'}),nessusListFolders:async()=>[{id:7,name:'Alpha',type:'custom'}],nessusListScans:async()=>[{id:9,folderId:7,name:'Scan',status:'completed',lastModified}],nessusScanStatus:async()=>({status:'completed',progress:100}),nessusImportFindings:async()=>get()},
};}
function initial(){const d=seed();d.scans=[['S-1',scan()]];d.findings=[['F-1',{...finding(),status:'Resolved',resolvedAt:'2026-10-02T00:00:00Z'}],['F-current',{...finding('F-current'),cve:'CVE-2026-99999'}],['F-stale',{...finding('F-stale'),cve:'CVE-2026-88888'}],['F-foreign',finding('F-foreign','CO-B')]];return d;}
test('Nessus completion persists new, duplicate, reopened and closed findings with aliases and exact scoped parity',async()=>{
 const run=async baseline=>{const h=await mutationHarness({disk:{value:initial()},providers:providers(),now,baseline});await h.store.refreshVendorScans(h.memory());await h.flush();h.assertPersisted();return h;};
 const h=await run(false),oracle=await run(true);assert.notEqual(h.lastScope(),undefined);assert.deepEqual(h.disk.value,oracle.disk.value);
 assert.deepEqual(new Set(h.lastScope().findings),new Set(['F-current','F-stale','VLN-1001']));assert.deepEqual(h.lastScope().scans,['S-1']);
 const rows=new Map(h.disk.value.findings);assert.equal(rows.get('F-1').status,'Resolved');assert.equal(rows.get('VLN-1001').status,'Open');assert.equal(rows.get('F-current').lastSeen,new Date(now).toISOString());assert.equal(rows.get('F-stale').status,'Resolved');assert.equal(rows.get('F-foreign').status,'Open');assert.equal(rows.size,5);
 const restarted=await mutationHarness({disk:h.disk,providers:providers(),now});restarted.assertPersisted();assert.equal(restarted.memory().scans.get('S-1').vendor.imported,true);
});
test('new Nessus import saves after an earlier commit during the provider request and unchanged repeat does no collection work',async()=>{
 let h;const p=providers(async()=>{await h.flush();assert.equal(h.disk.value.findings.length,0);return result();});
 h=await mutationHarness({providers:p,now});const imported=await h.store.importFromNessus();assert.equal(imported.scansImported,1);h.assertPersisted();assert.notEqual(h.lastScope(),undefined);
 assert.equal(h.disk.value.findings.length,2);assert.equal(h.disk.value.scans[0][1].vendor.imported,true);const count=h.saves.length;
 await h.store.importFromNessus();h.assertPersisted();assert.equal(h.saves.length,count,'unchanged run should not trigger another save');
});
test('Nessus provider failure does not close previous findings and can retry the same completed scan',async()=>{
 let fail=true;const p=providers(()=>{if(fail)throw Error('Provider failed before complete result');return result();});const h=await mutationHarness({disk:{value:initial()},providers:p,now});
 await h.store.refreshVendorScans(h.memory());await h.flush();h.assertPersisted();assert.equal(h.disk.value.scans[0][1].vendor.imported,false);assert.equal(new Map(h.disk.value.findings).get('F-stale').status,'Open');
 fail=false;await h.store.importFromNessus();h.assertPersisted();assert.equal(h.disk.value.scans.length,1);assert.equal(h.disk.value.scans[0][1].vendor.imported,true);
});
test('partial application failure saves touched records without a false completion marker or closure',async()=>{
 const partial=result();Object.defineProperty(partial.findings[1],'assetAliases',{get(){throw Error('Bad source record');}});
 const h=await mutationHarness({disk:{value:initial()},providers:providers(()=>partial),now});await h.store.refreshVendorScans(h.memory());await h.flush();h.assertPersisted();
 assert.notEqual(h.lastScope(),undefined);assert.equal(new Map(h.disk.value.findings).get('VLN-1001').status,'Open');assert.equal(new Map(h.disk.value.findings).get('F-stale').status,'Open');assert.equal(h.disk.value.scans[0][1].vendor.imported,false);
});
test('legacy Nessus backfill markers and counter survive a scoped save',async()=>{
 const d=initial();d.meta.nessusBackfillCorrected=false;d.scans[0][1].completedAt=now;d.scans[0][1].status='Completed';d.scans[0][1].vendor={nessusScanId:9,lastPoll:0,imported:true,nessusLastModified:1};
 const h=await mutationHarness({disk:{value:d},providers:providers(),now});await h.store.importFromNessus();h.assertPersisted();assert.notEqual(h.lastScope(),undefined);assert.equal(h.disk.value.meta.nessusBackfillCorrected,true);assert.equal(h.disk.value.scans[0][1].vendor.nessusLastModified,lastModified);
});
