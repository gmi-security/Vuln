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
 const queries=[],written=[];let onWrite,connections=0;
 const client={release(){},async query(sql,params){
  queries.push(sql);
  if(sql.includes('to_regclass'))return {rows:[{relation:'app_store_authority'}]};
  if(sql.includes('FROM public.app_store_authority'))return {rows:[auth]};
  if(sql.startsWith('INSERT INTO app_scans')){written.push(...JSON.parse(params[0]));const fn=onWrite;onWrite=undefined;fn?.();}
  if(sql.startsWith('UPDATE app_store_authority')){auth.revision=String(Number(auth.revision)+1);return {rows:[{...auth}]};}
  return {rows:[]};
 }};
 const pool={on(){},async query(){return {rows:[]}},async connect(){connections++;return client;}};
 const env={DATABASE_URL:'postgresql://localhost/unit-only',VULN_PLATFORM_STORE:'sql'};
 const context=createContext({Buffer,URL,process:{env},console:{info(){},error(){}},setTimeout,clearTimeout,setImmediate});
 const revisions={createReportingInputDigests:()=>({async bucket(){},finish:()=>[],committed(){}}),publishReportingInputRevisions:async()=>{},publishSqlReportingChanges:async()=>{},reportingSnapshotManifest:async()=>null};
 const code=ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const m=new SourceTextModule(code,{context});
 await m.link(name=>{const values=name==='pg'?{Pool:class{constructor(){return pool}}}:name.endsWith('customer-reporting-revisions.mjs')?revisions:name.endsWith('platform-store.mjs')?platform:name.endsWith('platform-authority.mjs')?authority:name.endsWith('platform-reader.mjs')?reader:crypto;return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v)},{context});});
 await m.evaluate();
 const state=context.__vulnDatabasePersistenceV1;
 state.platformAuthority={...auth};state.platformState={authority:{...auth},index,metaHash:platformHash(platformJson({counter:1}))};
 data.scans[0][1].progress=50;
 return {persist:m.namespace,data,queries,written,state,onWrite:fn=>{onWrite=fn},connections:()=>connections};
}

test('RAM changes during preparation reject the capture before a connection is borrowed',async()=>{
 const h=await harness();
 await assert.rejects(h.persist.saveSnapshot(h.data,{captureGuard(){throw Error('capture changed')}}),/capture changed/);
 assert.equal(h.connections(),0);
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

test('scoped writes keep the capture check until the transaction finishes',async()=>{
 const h=await harness();let changed=false;h.onWrite(()=>{changed=true});
 await assert.rejects(h.persist.saveSnapshot(h.data,{changes:{scans:['S-1']},captureGuard(){if(changed)throw Error('capture changed')}}),/capture changed/);
 assert.ok(!h.queries.includes('COMMIT'));
 assert.equal(h.state.platformAuthority.revision,'5');
});

test('general cancellation still aborts frozen writes after an INSERT',async()=>{
 const h=await harness();let cancelled=false;h.onWrite(()=>{cancelled=true});
 await assert.rejects(h.persist.saveSnapshot(h.data,{guard(){if(cancelled)throw Error('cancelled')}}),/cancelled/);
 assert.ok(!h.queries.includes('COMMIT'));
 assert.equal(h.state.platformAuthority.revision,'5');
});
