import assert from 'node:assert/strict';
import test from 'node:test';
import {savePlatformDelta} from '../lib/db/platform-store.mjs';
import {platformCollections,platformBucket,platformJson,platformHash} from '../lib/db/platform-records.mjs';
import * as platformStore from '../lib/db/platform-store.mjs';

test('large scoped imports have a bounded publication budget without extending ordinary saves',()=>{
 assert.equal(platformStore.platformSaveTimeoutMs?.(),300000);
 assert.equal(platformStore.platformSaveTimeoutMs?.({findings:['one']}),300000);
 assert.equal(platformStore.platformSaveTimeoutMs?.({findings:Array(100000).fill('fixture')}),1800000);
 assert.equal(platformStore.platformSaveTimeoutMs?.({findings:Array(1000000).fill('fixture')}),1800000);
});

test('bulk inserts allocate stable orders in memory and keep SQL writes batched',async()=>{
 const authority={mode:'sql',enforced:true,epoch:'2',revision:'5'};
 const queries=[],written=[];
 const client={async query(sql,params){
  queries.push(sql);
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[authority]};
  if(sql.startsWith('INSERT INTO app_findings'))written.push(...JSON.parse(params[0]));
  if(sql.startsWith('UPDATE app_store_authority'))return {rows:[{...authority,revision:'6'}]};
  return {rows:[]};
 }};
 const index=new Map(Object.keys(platformCollections).map(k=>[k,new Map()]));
 for(let b=0;b<64;b++)index.get('findings').set(`old-${b}`,{hash:'old',order:10240,bucket:b});
 const metadata={meta:{defenderGenerations:{'CO-A':'new-run'}}};
 const findings=Array.from({length:1501},(_,i)=>[`F-${i}`,{id:`F-${i}`,companyId:'CO-A',connector:'defender',cve:'CVE-2026-1234'}]);
 const state={authority,index,metaHash:platformHash(platformJson(metadata))};
 const result=await savePlatformDelta(client,{...metadata,findings},state,{findings:findings.map(([id])=>id)});
 assert.equal(written.length,1501);
 assert.equal(queries.filter(q=>q.startsWith('INSERT INTO app_findings')).length,4,'a large import must use batches, not one INSERT per new finding');
 assert.equal(queries.filter(q=>q.includes('SELECT store_order')).length,0,'the fenced loaded index already knows append orders');
 const last=new Map(Array.from({length:64},(_,b)=>[b,10240]));
 for(const row of written){const b=platformBucket(row.id,64);assert.equal(row.store_order,last.get(b)+1024);last.set(b,row.store_order);}
 assert.equal(result.counts.inserted,1501);
 assert.equal(state.index.get('findings').size,64,'the loaded index changes only after commit');
});
