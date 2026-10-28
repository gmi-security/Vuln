import assert from 'node:assert/strict';
import test from 'node:test';
import {platformRecord,platformCollections,platformHash,platformJson} from '../lib/db/platform-records.mjs';
import {loadPlatformStore,savePlatformStore,savePlatformDelta} from '../lib/db/platform-store.mjs';
import {loadCommittedPlatform as load} from '../lib/db/platform-reader.mjs';

// Only PostgreSQL transport is faked; the reader, row validation, writer diff,
// and audit publication execute unchanged against complete SQL-shaped rows.
const metadata={counter:42,meta:{defenderGenerations:{'CO-1':'run-old'}},settings:{schedule:{autoSyncEnabled:true}}};
const authority={mode:'sql',enforced:true,epoch:'2',revision:'5'};
const row=(kind,id,extra={},order=1024)=>platformRecord(kind,[id,{id,...extra}],order);
function database(){
 const state={authority:{...authority},metadata:structuredClone(metadata),metadataHash:null,commits:[],
  records:new Map(Object.keys(platformCollections).map(kind=>[kind,[]])),reads:[],writes:[],audits:[]};
 state.records.set('companies',[row('companies','CO-1',{name:'Customer'})]);
 state.records.set('findings',[row('findings','F-1',{companyId:'CO-1',status:'Open',future:{evidence:'kept'}}),row('findings','F-2',{companyId:'CO-1',status:'Open'})]);
 const client={async query(sql,params=[]){
  if(sql.includes('to_regclass'))return {rows:[{relation:sql.includes('app_finding_head')?null:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[{...state.authority}]};
  if(sql.startsWith('SELECT set_config'))return {rows:[]};
  if(sql.includes('FROM app_store_commits')){state.reads.push('commits');return {rows:structuredClone(state.commits)};}
  if(sql.includes('FROM public.app_store_metadata')||sql.includes('FROM app_store_metadata')){
   state.reads.push('meta');return {rows:[{data:structuredClone(state.metadata),payload:structuredClone(state.metadata),record_hash:state.metadataHash??platformHash(platformJson(state.metadata))}]};
  }
  const collection=Object.entries(platformCollections).find(([,config])=>sql.includes(`FROM ${config.table}`));
  if(sql.startsWith('SELECT id,company_id,store_bucket')&&collection){
   return {rows:state.records.get(collection[0]).filter(r=>params[0].includes(r.id)).map(({id,company_id,store_bucket})=>({id,company_id,store_bucket}))};
  }
  if(sql.startsWith('SELECT id,payload,record_hash,store_order')&&collection){
   const [kind]=collection,[bucket,after,afterId]=params;state.reads.push(`${kind}:${String(bucket).padStart(2,'0')}`);
   return {rows:structuredClone(state.records.get(kind).filter(r=>r.store_bucket===bucket&&(r.store_order>after||(r.store_order===after&&r.id>afterId)))
    .sort((a,b)=>a.store_order-b.store_order||a.id.localeCompare(b.id)).slice(0,500))};
  }
  state.writes.push(sql);
  if(sql.startsWith('UPDATE app_store_authority')){state.authority={...state.authority,revision:String(BigInt(state.authority.revision)+1n)};return {rows:[{...state.authority}]};}
  if(sql.startsWith('INSERT INTO app_store_commits'))state.audits.push({epoch:params[1],revision:params[2],operation:params[3],counts:JSON.parse(params[5])});
  if(/^(INSERT INTO app_|UPDATE app_store_metadata|DELETE FROM app_)/.test(sql))return {rows:[]};
  throw Error(`Unexpected SQL: ${sql}`);
 }};
 return {state,client};
}
function advance(state,commits){state.commits=commits;state.authority={...state.authority,revision:commits.at(-1).revision};state.reads.length=0;}
const commit=(revision,counts)=>({epoch:'2',revision,operation:'save',counts});
const counts=(changedKeys,extra={})=>({inserted:0,updated:0,deleted:0,metadata:0,...extra,...(changedKeys===undefined?{}:{changedKeys})});

test('initial committed view validates rows and prevents caller mutation without a writer index',async()=>{
 const {state,client}=database(),snapshot=await load(client);
 assert.equal(snapshot.authority.revision,'5');assert.equal(snapshot.buckets.size,90);
 assert.deepEqual(snapshot.buckets.get('findings:55'),[['F-1',{id:'F-1',companyId:'CO-1',status:'Open',future:{evidence:'kept'}}]]);
 assert.equal(snapshot.metadata.counter,42);assert.equal(snapshot.index,undefined);assert.equal(snapshot.changedKeys.length,91);
 assert.throws(()=>snapshot.buckets.set('findings:55',[]),/immutable|read.only/i);
 assert.throws(()=>snapshot.buckets.get('findings:55')[0][1].future.evidence='changed',TypeError);
 assert.throws(()=>snapshot.metadata.meta.defenderGenerations['CO-1']='changed',TypeError);
 assert.equal(state.writes.length,0,'reader must never initialize schema or mutate SQL');
});

test('unchanged authority returns the previous snapshot without rereading metadata or findings',async()=>{
 const {state,client}=database(),previous=await load(client);state.reads.length=0;
 assert.equal(await load(client,previous),previous);assert.deepEqual(state.reads,[]);
});

test('legacy metadata-only commits refresh metadata without loading any collection',async()=>{
 const {state,client}=database(),previous=await load(client);
 state.metadata.meta.defenderGenerations['CO-1']='run-new';
 advance(state,[commit('6',counts(undefined,{metadata:1}))]);
 const next=await load(client,previous);
 assert.equal(next.metadata.meta.defenderGenerations['CO-1'],'run-new');assert.equal(previous.metadata.meta.defenderGenerations['CO-1'],'run-old');
 assert.equal(next.buckets,previous.buckets);assert.deepEqual(next.changedKeys,['meta']);
 assert.ok(state.reads.every(key=>['meta','commits'].includes(key)),'metadata bookkeeping must not deserialize findings');
});

test('contiguous audited changes replace only touched buckets including deletions',async()=>{
 const {state,client}=database(),previous=await load(client);
 state.records.set('findings',[row('findings','F-1',{companyId:'CO-1',status:'Resolved'}),row('findings','F-NEW',{companyId:'CO-1',status:'Open'})]);
 advance(state,[commit('6',counts(['findings:55'],{updated:1})),commit('7',counts(['findings:21','findings:47'],{deleted:1,inserted:1}))]);
 const next=await load(client,previous);
 assert.deepEqual(next.changedKeys,['findings:21','findings:47','findings:55']);
 assert.deepEqual([...new Set(state.reads.filter(key=>!['meta','commits'].includes(key)))].sort(),['findings:21','findings:47','findings:55']);
 assert.deepEqual(next.buckets.get('findings:21'),[]);assert.equal(next.buckets.get('findings:55')[0][1].status,'Resolved');
 assert.equal(next.buckets.get('findings:47')[0][0],'F-NEW');assert.equal(previous.buckets.get('findings:55')[0][1].status,'Open');
 assert.equal(previous.buckets.get('findings:21')[0][0],'F-2');assert.equal(next.buckets.get('companies:00'),previous.buckets.get('companies:00'));
 assert.equal(next.metadata,previous.metadata);assert.notEqual(next.buckets,previous.buckets);
});

for(const [name,commits] of [
 ['missing commit',[commit('7',counts(['meta'],{metadata:1}))]],
 ['wrong epoch',[{...commit('6',counts(['meta'],{metadata:1})),epoch:'1'}]],
 ['legacy row changes',[commit('6',counts(undefined,{updated:1}))]],
 ['unknown bucket',[commit('6',counts(['findings:99'],{updated:1}))]],
 ['string counters',[commit('6',counts(['meta'],{inserted:'0',metadata:1}))]],
 ['missing changed collection',[commit('6',counts(['meta'],{updated:1,metadata:1}))]],
 ['duplicate keys',[commit('6',counts(['meta','meta'],{metadata:1}))]],
 ['non-save commit',[{...commit('6',counts(['meta'],{metadata:1})),operation:'backfill'}]],
])test(`${name} falls back to a complete verified snapshot`,async()=>{
 const {state,client}=database(),previous=await load(client);
 state.records.get('findings')[0]=row('findings','F-1',{companyId:'CO-1',status:'Resolved'});
 advance(state,commits);const next=await load(client,previous);
 assert.equal(next.buckets.get('findings:55')[0][1].status,'Resolved');assert.equal(next.changedKeys.length,91);
 assert.ok(state.reads.includes('assets:15'));assert.equal(previous.buckets.get('findings:55')[0][1].status,'Open');
});

test('an epoch change reloads all collections instead of applying another epoch audit',async()=>{
 const {state,client}=database(),previous=await load(client);state.authority={...state.authority,epoch:'3',revision:'0'};state.reads.length=0;
 const next=await load(client,previous);assert.equal(next.authority.epoch,'3');assert.equal(next.changedKeys.length,91);assert.ok(state.reads.includes('findings:00'));
});

test('failed bucket validation leaves the published previous snapshot intact',async()=>{
 const {state,client}=database(),previous=await load(client);
 state.records.get('findings')[0].record_hash='0'.repeat(64);
 advance(state,[commit('6',counts(['findings:55'],{updated:1}))]);
 await assert.rejects(load(client,previous),/checksum/);
 assert.equal(previous.authority.revision,'5');assert.equal(previous.buckets.get('findings:55')[0][1].future.evidence,'kept');
 assert.equal(previous.metadata.meta.defenderGenerations['CO-1'],'run-old');
});

test('bad metadata checksums fail even when an audit only names finding buckets',async()=>{
 const {state,client}=database(),previous=await load(client);state.metadataHash='0'.repeat(64);
 advance(state,[commit('6',counts(['findings:55'],{updated:1}))]);
 await assert.rejects(load(client,previous),/metadata checksum/);assert.equal(previous.authority.revision,'5');
});

test('misbucketed or invalid-order rows are rejected during a full load',async()=>{
 for(const patch of [{store_bucket:0},{store_order:Infinity}]){
  const {state,client}=database();Object.assign(state.records.get('findings')[0],patch);
  await assert.rejects(load(client),/bucket|order/);
 }
});

test('full writer audits actual changed buckets, deletions and metadata without changing counts contract',async()=>{
 const {state,client}=database(),loaded=await loadPlatformStore(client,state.authority),data=structuredClone(loaded.data);
 data.findings=data.findings.filter(([id])=>id!=='F-2');data.findings[0][1].status='Resolved';
 data.findings.push(['F-NEW',{id:'F-NEW',companyId:'CO-1',status:'Open'}]);data.counter++;
 const saved=await savePlatformStore(client,data,loaded.state);
 assert.deepEqual(saved.counts,{inserted:1,updated:1,deleted:1,metadata:1});
 assert.deepEqual(state.audits[0].counts.changedKeys,['findings:21','findings:47','findings:55','meta']);
 assert.equal(saved.changedKeys,undefined,'full writers retain the existing complete reporting publication path');
});

test('delta writer audits removed buckets and metadata in the same revision record',async()=>{
 const {state,client}=database(),loaded=await loadPlatformStore(client,state.authority);
 const saved=await savePlatformDelta(client,{...metadata,counter:43,findings:[]},loaded.state,{findings:['F-2']});
 assert.deepEqual(saved.counts,{inserted:0,updated:0,deleted:1,metadata:1});
 assert.deepEqual(state.audits[0].counts.changedKeys,['findings:21','meta']);assert.equal(state.audits[0].revision,saved.authority.revision);
});
