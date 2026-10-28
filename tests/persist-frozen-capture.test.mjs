import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {createContext,SourceTextModule,SyntheticModule} from 'node:vm';
import * as crypto from 'node:crypto';
import ts from 'typescript';
import * as platform from '../lib/db/platform-store.mjs';
import * as authority from '../lib/db/platform-authority.mjs';
import * as reader from '../lib/db/platform-reader.mjs';
import {platformCollections,platformRecord,platformHash,platformJson} from '../lib/db/platform-records.mjs';

async function harness(){
 const auth={mode:'sql',enforced:true,epoch:'2',revision:'5'};
 const data={counter:1,...Object.fromEntries(Object.keys(platformCollections).map(k=>[k,[]]))};
 data.scans=[['S-1',{id:'S-1',progress:10}]];
 const index=new Map(Object.keys(platformCollections).map(k=>[k,new Map()]));
 const record=platformRecord('scans',data.scans[0],1024);
 index.get('scans').set('S-1',{hash:record.record_hash,order:record.store_order,bucket:record.store_bucket});
 const queries=[],written=[],reported=[],released=[],waits=[];let onWrite,onQuery,connections=0,deadline;
 const client=()=>{let pending={...auth},closed=false;return {release(error){closed=true;released.push(error);},async query(sql,params){
  if(closed)throw Error('closed connection');
  queries.push(sql);
  await onQuery?.(sql);
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[auth]};
  if(sql.startsWith('INSERT INTO app_scans')){written.push(...JSON.parse(params[0]));const fn=onWrite;onWrite=undefined;await fn?.();}
  if(sql.startsWith('UPDATE app_store_authority')){pending.revision=String(Number(auth.revision)+1);return {rows:[{...pending}]};}
  if(sql==='COMMIT')Object.assign(auth,pending);
  return {rows:[]};
 }}};
 const pool={on(){},async query(){return {rows:[]}},async connect(){connections++;return client();}};
 const env={DATABASE_URL:'postgresql://localhost/unit-only',VULN_PLATFORM_STORE:'sql'};
 const context=createContext({Buffer,URL,process:{env},console:{info(){},error(){},warn(){}},setTimeout:(fn,ms)=>{
  if(ms>=300000)deadline=fn;
  if(ms===30000){waits.push(ms);return setTimeout(fn,0);}
  return setTimeout(fn,ms);
 },clearTimeout,setImmediate});
 const revisions={createReportingInputDigests:()=>({async bucket(){},finish:()=>[],committed(){}}),publishReportingInputRevisions:async()=>{},publishSqlReportingChanges:async(c,k,t,plan)=>{reported.push(plan);},reportingSnapshotManifest:async()=>null};
 const code=ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const m=new SourceTextModule(code,{context});
 let reportError;
 const storeModule={...platform,preparePlatformReporting:async(p,plan)=>{if(reportError)throw reportError;reported.push(plan);return [];}};
 await m.link(name=>{const values=name==='pg'?{Pool:class{constructor(){return pool}}}:name.endsWith('customer-reporting-revisions.mjs')?revisions:name.endsWith('platform-store.mjs')?storeModule:name.endsWith('platform-authority.mjs')?authority:name.endsWith('platform-reader.mjs')?reader:crypto;return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v)},{context});});
 await m.evaluate();
 const state=context.__vulnDatabasePersistenceV1;
 state.platformAuthority={...auth};state.platformState={authority:{...auth},index,metaHash:platformHash(platformJson({counter:1}))};
 data.scans[0][1].progress=50;
 return {persist:m.namespace,data,queries,written,reported,state,released,waits,auth,reportError:e=>{reportError=e},onWrite:fn=>{onWrite=fn},onQuery:fn=>{onQuery=fn},expire:()=>deadline(),connections:()=>connections};
}

test('RAM changes during preparation reject the capture before a connection is borrowed',async()=>{
 const h=await harness();
 await assert.rejects(h.persist.saveSnapshot(h.data,{captureGuard(){throw Error('capture changed')}}),/capture changed/);
 assert.equal(h.connections(),0);
});
test('reporting preparation finishes before any authoritative row writes',async()=>{
 const h=await harness();h.onWrite(()=>{assert.equal(h.reported.length,1,'reporting must be prepared before opening the write transaction');});
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});
 assert.equal(h.reported.length,1);
});
for(const message of ['Connection terminated unexpectedly','Connection terminated due to connection timeout','timeout exceeded when trying to connect'])
test(`private preparation safely defers pg transport error: ${message}`,async()=>{
 const h=await harness();h.reportError(new Error(message));
 await assert.rejects(h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}}),e=>e.code==='platform-publication-deferred');
 assert.equal(h.written.length,0);assert.equal(h.state.platformAuthority.revision,'5');
 h.reportError(undefined);await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});
 assert.equal(h.state.platformAuthority.revision,'6');
});

test('a frozen capture commits despite later RAM changes and the next save retains them',async()=>{
 const h=await harness();let changed=false,checks=0;
 h.onWrite(()=>{changed=true;h.data.scans[0][1].progress=90;});
 await h.persist.saveSnapshot(h.data,{captureGuard(){checks++;if(changed)throw Error('capture changed')}});
 assert.ok(checks>1,'capture is checked throughout preparation');
 assert.equal(h.written[0].payload.progress,50);
 assert.equal(h.queries.filter(q=>q==='COMMIT').length,1);
 await h.persist.saveSnapshot(h.data);
 assert.equal(h.written[1].payload.progress,90);
 assert.equal(h.state.platformAuthority.revision,'7');
});

test('scoped frozen writes commit one capture and preserve a later mutation for the next save',async()=>{
 const h=await harness();let changed=false;h.onWrite(()=>{changed=true;h.data.scans[0][1].progress=90});
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']},captureGuard(){if(changed)throw Error('capture changed')}});
 assert.equal(h.written[0].payload.progress,50);assert.equal(h.state.platformAuthority.revision,'6');
 assert.equal(h.reported[0].writes.get('scans')[0].payload.progress,50,'reporting receives the same detached generation as SQL');
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});assert.equal(h.written[1].payload.progress,90);
});

test('general cancellation still aborts frozen writes after an INSERT',async()=>{
 const h=await harness();let cancelled=false;h.onWrite(()=>{cancelled=true});
 await assert.rejects(h.persist.saveSnapshot(h.data,{guard(){if(cancelled)throw Error('cancelled')}}),/cancelled/);
 assert.ok(!h.queries.includes('COMMIT'));
 assert.equal(h.state.platformAuthority.revision,'5');
});

test('a timed-out transaction retries the same frozen capture on a fresh fenced connection',async()=>{
 const h=await harness();h.onWrite(async()=>{h.data.scans[0][1].progress=90;h.expire();await new Promise(r=>setImmediate(r));});
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});
 assert.equal(h.connections(),2);assert.equal(h.released.length,2);assert.ok(h.released[0]);
 assert.deepEqual(h.waits,[30000]);assert.deepEqual(h.written.map(r=>r.payload.progress),[50,50]);
 assert.equal(h.queries.filter(q=>q==='COMMIT').length,1);assert.equal(h.state.platformAuthority.revision,'6');
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});
 assert.equal(h.written.at(-1).payload.progress,90);assert.equal(h.auth.revision,'7');
});

for(const code of ['57014','55P03','40P01','40001'])test(`temporary SQL ${code} retries once without advancing the committed index early`,async()=>{
 const h=await harness();let failed=false;h.onQuery(sql=>{
  if(sql.startsWith('INSERT INTO app_scans')&&!failed){failed=true;throw Object.assign(Error('temporary SQL error'),{code});}
 });
 await h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}});
 assert.equal(h.connections(),2);assert.equal(h.auth.revision,'6');assert.equal(h.state.platformAuthority.revision,'6');
});

test('a repeated timeout is bounded to two attempts and preserves the prior index',async()=>{
 const h=await harness();h.onQuery(sql=>{if(sql.startsWith('INSERT INTO app_scans'))throw Object.assign(Error('timeout'),{code:'57014'});});
 await assert.rejects(h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}}),/timeout/);
 assert.equal(h.connections(),2);assert.equal(h.state.platformAuthority.revision,'5');assert.equal(h.auth.revision,'5');
});

test('a newer database revision fences the retry before any second write',async()=>{
 const h=await harness();let failed=false;h.onQuery(sql=>{
  if(sql.startsWith('INSERT INTO app_scans')&&!failed){failed=true;h.auth.revision='9';throw Object.assign(Error('lock timeout'),{code:'55P03'});}
 });
 await assert.rejects(h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}}),/authority changed/);
 assert.equal(h.connections(),2);assert.equal(h.written.length,0);assert.equal(h.state.platformAuthority.revision,'5');
});

for(const [phase,code] of [['COMMIT','57014'],['INSERT INTO app_scans','08006'],['INSERT INTO app_scans','23505']])test(`uncertain or unsafe failure ${phase}/${code} does not retry`,async()=>{
 const h=await harness();h.onQuery(sql=>{if(sql.startsWith(phase))throw Object.assign(Error('unsafe failure'),{code});});
 await assert.rejects(h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']}}),/unsafe failure/);
 assert.equal(h.connections(),1);assert.equal(h.waits.length,0);assert.equal(h.state.platformAuthority.revision,'5');
});
