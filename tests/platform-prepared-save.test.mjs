import assert from 'node:assert/strict';
import test from 'node:test';
import * as store from '../lib/db/platform-store.mjs';
import {platformCollections,platformRecord,platformJson,platformHash} from '../lib/db/platform-records.mjs';

function fixture(){
 const authority={mode:'sql',enforced:true,epoch:'2',revision:'5'};
 const data={counter:1,...Object.fromEntries(Object.keys(platformCollections).map(k=>[k,[]]))};
 data.scans=[['S-1',{id:'S-1',progress:10}]];
 data.findings=Array.from({length:1001},(_,i)=>[`F-${i}`,{id:`F-${i}`,companyId:'CO-1',status:'Open',evidence:{value:'original'}}]);
 const index=new Map(Object.keys(platformCollections).map(k=>[k,new Map()]));
 for(const [kind] of Object.entries(platformCollections))for(const entry of data[kind]){
  const r=platformRecord(kind,entry,1024*(index.get(kind).size+1));
  index.get(kind).set(r.id,{hash:r.record_hash,order:r.store_order,bucket:r.store_bucket});
 }
 const state={authority,index,metaHash:platformHash(platformJson({counter:1}))},queries=[],written=[];
 const client={async query(sql,params){
  queries.push(sql);
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[authority]};
  if(sql.startsWith('INSERT INTO app_findings')||sql.startsWith('INSERT INTO app_scans'))written.push(...JSON.parse(params[0]));
  if(sql.startsWith('UPDATE app_store_authority'))return {rows:[{...authority,revision:'6'}]};
  return {rows:[]};
 }};
 return {data,state,queries,written,client,authority};
}

test('full comparison and reporting finish before any SQL; one scan edit writes no findings',async()=>{
 const f=fixture();f.data.scans[0][1].progress=50;
 const buckets=[];
 const plan=await store.preparePlatformStore(f.data,f.state,{reporting:{async bucket(key){assert.equal(f.queries.length,0);buckets.push(key);}}});
 assert.equal(f.queries.length,0);assert.equal(plan.counts.updated,1);assert.equal(plan.findingChanges,0);
 assert.equal(buckets.length,91);
 const result=await store.commitPreparedPlatformStore(f.client,plan);
 assert.equal(result.counts.updated,1);assert.equal(f.written.length,1);
 assert.equal(f.written[0].payload.progress,50);assert.equal(result.changedKeys,undefined);
 assert.equal(f.state.authority.revision,'5');assert.equal(result.authority.revision,'6');
});

test('prepared rows and reporting use the same frozen capture, not later RAM mutations',async()=>{
 const f=fixture();f.data.findings[0][1].status='Resolved';const reported=[];
 const plan=await store.preparePlatformStore(f.data,f.state,{reporting:{async bucket(key,json){if(key.startsWith('findings:'))reported.push(...JSON.parse(json));}}});
 f.data.findings[0][1].evidence.value='later';f.data.findings[0][1].status='Open';
 await store.commitPreparedPlatformStore(f.client,plan);
 assert.deepEqual(f.written[0].payload,reported.find(([id])=>id==='F-0')[1]);
 assert.equal(f.written[0].payload.evidence.value,'original');assert.equal(plan.findingChanges,1);
});

test('stale authority after preparation is refused before any record writes',async()=>{
 const f=fixture();f.data.scans[0][1].progress=50;
 const plan=await store.preparePlatformStore(f.data,f.state);
 f.authority.revision='6';
 await assert.rejects(store.commitPreparedPlatformStore(f.client,plan),/revision|changed|stale/i);
 assert.equal(f.written.length,0);assert.equal(f.state.index.get('scans').get('S-1').hash,platformRecord('scans',['S-1',{id:'S-1',progress:10}],1024).record_hash);
});

test('capture guard prevents starting a prepared write after intervening mutations',async()=>{
 const f=fixture();f.data.scans[0][1].progress=50;const plan=await store.preparePlatformStore(f.data,f.state);
 await assert.rejects(store.commitPreparedPlatformStore(f.client,plan,{guard(){throw Error('capture changed');}}),/capture changed/);
 assert.equal(f.queries.length,0);
});

test('preparation failure never reaches SQL and leaves committed index intact',async()=>{
 const f=fixture();f.data.scans[0][1].progress=50;
 await assert.rejects(store.preparePlatformStore(f.data,f.state,{guard(){throw Error('capture changed');}}),/capture changed/);
 assert.equal(f.queries.length,0);assert.equal(f.state.authority.revision,'5');
});

test('full preparation preserves deletes, metadata, and 500-row write batches',async()=>{
 const f=fixture();f.data.findings.shift();for(const [,r]of f.data.findings)r.status='Resolved';f.data.counter=2;
 const plan=await store.preparePlatformStore(f.data,f.state);
 assert.equal(plan.findingChanges,1001);
 const result=await store.commitPreparedPlatformStore(f.client,plan);
 assert.deepEqual(result.counts,{inserted:0,updated:1000,deleted:1,metadata:1});
 assert.equal(f.written.length,1000);assert.ok(f.queries.some(q=>q.startsWith('DELETE FROM app_findings')));
 assert.equal(f.state.index.get('findings').size,1001);assert.equal(result.index.get('findings').size,1000);
});

test('actual full-import changes receive the same bounded budget as explicit imports',()=>{
 assert.equal(store.platformSaveTimeoutMs(undefined,1),300000);
 assert.equal(store.platformSaveTimeoutMs(undefined,100000),900000);
});

test('comparison counts distinguish a scoped save from hashing the whole collection',async()=>{
 const f=fixture();f.data.scans[0][1].progress=50;
 const full=await store.preparePlatformStore(f.data,f.state);
 assert.equal(full.comparedRecords,1002);
 f.data.findings[0][1].toJSON=()=>{throw Error('Unrelated finding was serialized');};
 const delta=await store.savePlatformDelta(f.client,f.data,f.state,{scans:['S-1']});
 assert.equal(delta.comparedRecords,1);
 assert.equal(delta.counts.updated,1);
});

test('scoped preparation freezes only declared payloads before SQL and retains deletes, orders and metadata',async()=>{
 const f=fixture();f.data.counter=2;f.data.findings=f.data.findings.filter(([id])=>id!=='F-1');f.data.findings[0][1].status='Resolved';
 f.data.findings.push(['F-new',{id:'F-new',companyId:'CO-1',status:'Open'}]);
 f.data.findings.find(([id])=>id==='F-2')[1].toJSON=()=>{throw Error('Unrelated payload serialized');};
 assert.equal(typeof store.preparePlatformDelta,'function');
 const plan=await store.preparePlatformDelta(f.data,f.state,{findings:['F-0','F-1','F-new']});
 assert.equal(f.queries.length,0);assert.equal(plan.comparedRecords,2);assert.equal(plan.findingChanges,3);
 f.data.findings[0][1].status='Later edit';f.data.counter=3;
 const result=await store.commitPreparedPlatformStore(f.client,plan);
 assert.equal(f.written.find(r=>r.id==='F-0').payload.status,'Resolved');assert.deepEqual(result.counts,{inserted:1,updated:1,deleted:1,metadata:1});
 assert.ok(result.changedKeys.includes('meta'));assert.equal(result.index.get('findings').get('F-0').order,f.state.index.get('findings').get('F-0').order);
 assert.ok(f.state.index.get('findings').has('F-1'));assert.ok(!result.index.get('findings').has('F-1'));
});

test('scoped preparation rejects invalid scope or a changed capture before SQL',async()=>{
 const f=fixture();assert.equal(typeof store.preparePlatformDelta,'function');
 for(const changes of [{findings:['F-0','F-0']},{unknown:['F-0']},{findings:[null]}])await assert.rejects(store.preparePlatformDelta(f.data,f.state,changes),/scope/);
 await assert.rejects(store.preparePlatformDelta(f.data,f.state,{findings:['F-0']},{guard(){throw Error('capture changed');}}),/capture changed/);
 assert.equal(f.queries.length,0);
});
