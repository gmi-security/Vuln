// Synthetic save-preparation comparison; no database, provider traffic or secrets.
// node --expose-gc tests/connector-save-benchmark.mjs 100000
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {monitorEventLoopDelay,performance} from 'node:perf_hooks';
import {preparePlatformStore,preparePlatformDelta} from '../lib/db/platform-store.mjs';
import {platformCollections,platformRecord,platformJson,platformHash} from '../lib/db/platform-records.mjs';
import {createReportingInputDigests} from '../lib/db/customer-reporting-revisions.mjs';
const scenarios=['asset','scan','inventory','nessus-customer','defender-customer','unchanged-customer'];
if(process.argv[2]!=='--case'){
 const rows=Number(process.argv[2]??100000);assert.ok(Number.isInteger(rows)&&rows>=10000&&rows<=1000000);
 const results=[];
 for(const scenario of scenarios){
  const pair=[];
  for(const mode of ['full','scoped']){
   const child=spawnSync(process.execPath,['--expose-gc',fileURLToPath(import.meta.url),'--case',scenario,String(rows),mode],{encoding:'utf8',maxBuffer:1024*1024});
   assert.equal(child.status,0,child.stderr);pair.push(JSON.parse(child.stdout));
  }
  assert.deepEqual(pair[0].writes,pair[1].writes,'Both paths must produce identical row/metadata counts');results.push({scenario,full:pair[0],scoped:pair[1]});
 }
 console.log(JSON.stringify({recordCount:rows,environment:{node:process.version,platform:process.platform,arch:process.arch},limits:'Synthetic preparation only. Full includes report digest preparation; scoped reporting occurs in SQL and is measured separately. Peak RSS includes fixture setup. Provider time and production HTTP latency are not measured.',results},null,2));
}else{
 const scenario=process.argv[3],rows=Number(process.argv[4]),mode=process.argv[5];
 const metadata={counter:rows+1000,settings:{},meta:{}};
 const data={...metadata,...Object.fromEntries(Object.keys(platformCollections).map(kind=>[kind,[]]))};
 for(let i=0;i<4;i++)data.companies.push([`CO-${i}`,{id:`CO-${i}`,name:`Synthetic ${i}`,kind:'client'}]);
 data.assets=Array.from({length:1000},(_,i)=>[`A-${i}`,{id:`A-${i}`,companyId:`CO-${i%4}`,identifier:`host-${i}`,hostname:`host-${i}`,source:'automate',os:'Windows'}]);
 data.scans=[['S-1',{id:'S-1',companyId:'CO-0',connector:'nessus',progress:10}]];
 data.findings=Array.from({length:rows},(_,i)=>[`F-${i}`,{id:`F-${i}`,companyId:`CO-${i%4}`,connector:i%2?'defender':'nessus',asset:`host-${i%1000}`,cve:`CVE-2026-${10000+i%10000}`,severity:'High',status:'Open',cvss:8,realRisk:44.5,lastSeen:'2026-10-01T00:00:00Z',remediation:'Synthetic remediation. '.repeat(30),evidence:{detail:'Synthetic evidence. '.repeat(20)}}]);
 const index=new Map();
 for(const kind of Object.keys(platformCollections)){
  const map=new Map(),orders=new Map();index.set(kind,map);
  for(const entry of data[kind]){const r=platformRecord(kind,entry,1024),order=(orders.get(r.store_bucket)??0)+1024;orders.set(r.store_bucket,order);map.set(r.id,{hash:r.record_hash,order,bucket:r.store_bucket});}
 }
 const state={authority:{mode:'sql',enforced:true,epoch:'2',revision:'1'},index,metaHash:platformHash(platformJson(metadata))};
 let changes;
 if(scenario==='asset'){data.assets[0][1].os='Linux';changes={assets:['A-0']};}
 else if(scenario==='scan'){data.scans[0][1].progress=80;changes={scans:['S-1']};}
 else{
  const candidates=data.findings.filter(([,row],i)=>scenario==='inventory'?i<100:row.companyId===(scenario==='defender-customer'?'CO-1':'CO-0'));
  for(const[,row]of candidates)if(scenario!=='unchanged-customer'){row.lastSeen='2026-10-15T00:00:00Z';row.realRisk=60;}
  changes={findings:candidates.map(([id])=>id)};
  if(scenario==='inventory'){changes.assets=data.assets.slice(0,10).map(([id])=>id);for(const[,row]of data.assets.slice(0,10))row.os='Linux';}
 }
 const selected=Object.fromEntries(Object.entries(changes).map(([kind,ids])=>[kind,new Set(ids)]));
 const input=mode==='full'?data:{...metadata,...Object.fromEntries(Object.keys(platformCollections).map(kind=>[kind,data[kind].filter(([id])=>selected[kind]?.has(id))]))};
 global.gc?.();const heapBefore=process.memoryUsage().heapUsed,delay=monitorEventLoopDelay({resolution:10});delay.enable();await new Promise(r=>setTimeout(r,25));delay.reset();
 const cpu=process.cpuUsage(),start=performance.now();
 const plan=mode==='full'?await preparePlatformStore(input,state,{reporting:createReportingInputDigests()}):await preparePlatformDelta(input,state,changes);
 const elapsedMs=performance.now()-start,cpuTime=process.cpuUsage(cpu);await new Promise(r=>setImmediate(r));delay.disable();
 console.log(JSON.stringify({elapsedMs:Math.round(elapsedMs),cpuMs:Math.round((cpuTime.user+cpuTime.system)/1000),comparedRecords:plan.comparedRecords,writes:plan.counts,...(plan.timings?{indexCopyMs:Math.round(plan.timings.indexCopyMs),recordPreparationMs:Math.round(plan.timings.recordPreparationMs)}:{}),heapGrowthMiB:Math.round((process.memoryUsage().heapUsed-heapBefore)/1048576),peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024),eventLoopMaxMs:Math.round(delay.max/1e6)}));
}
