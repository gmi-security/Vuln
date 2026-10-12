// Isolated Unix-socket recovery cluster only. Never loads application secrets.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {platformCollections,platformBucket,platformJson} from '../lib/db/platform-records.mjs';
import {readPlatformAuthority,bindPlatformWriter} from '../lib/db/platform-authority.mjs';
import {loadPlatformStore,savePlatformStore,transitionPlatformStore} from '../lib/db/platform-store.mjs';
import * as authorityModule from '../lib/db/platform-authority.mjs';
import * as storeModule from '../lib/db/platform-store.mjs';
import * as revisionModule from '../lib/db/customer-reporting-revisions.mjs';
import * as crypto from 'node:crypto';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name='vuln2_platform_test_'+randomUUID().replaceAll('-','');
const admin=new pg.Client({...config,database:'postgres'});let db,other,created=false,checks=0;
const ok=message=>{checks++;console.log('PASS '+message);};
async function tx(client,fn){await client.query('BEGIN');try{const r=await fn();await client.query('COMMIT');return r;}catch(e){await client.query('ROLLBACK');throw e;}}
const sources=['crowdstrike','defender','nessus','spiderfoot','artemis','zap','vulners','github'];
const fixture={companies:[['CO-1',{id:'CO-1',name:'Test',kind:'client'}]],folders:[],scans:[],assets:[],
 findings:Array.from({length:1400},(_,i)=>[`F-${i}`,{id:`F-${i}`,companyId:'CO-1',connector:sources[i%sources.length],cve:`CVE-2026-${10000+i}`,realRisk:44.5,status:'Open',future:{providerField:i}}]),
 counter:2000,settings:{sla:{Critical:7,High:30,Medium:90,Low:180}},identityAliases:[['ip','host']],meta:{sourceGenerations:{defender:'one'}},futureMetadata:{keep:true}};
const normalized=value=>Object.fromEntries(Object.entries(value).map(([k,v])=>[k,platformCollections[k]?[...v].sort(([a],[b])=>a.localeCompare(b)):v]));
try{
 await admin.connect();const guard=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Client({...config,database:name});other=new pg.Client({...config,database:name});await db.connect();await other.connect();
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())');
 for(const [kind,c] of Object.entries(platformCollections))for(let b=0;b<c.buckets;b++)await db.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',
  [`${kind}:${String(b).padStart(2,'0')}`,JSON.stringify(fixture[kind].filter(([id])=>platformBucket(id,c.buckets)===b))]);
 await db.query("INSERT INTO vuln_store(key,data) VALUES('meta',$1)",[JSON.stringify(Object.fromEntries(Object.entries(fixture).filter(([k])=>!platformCollections[k])))]);
 for(const file of ['001_core_storage.sql','002_platform_store_authority.sql']){const sql=await readFile('db/migrations/'+file,'utf8');await tx(db,()=>db.query(sql));}
 // The schema is additive; legacy writes remain usable until explicit cutover.
 const initial=await readPlatformAuthority(db);assert.equal(initial.mode,'legacy');assert.equal(initial.enforced,false);
 await db.query("UPDATE vuln_store SET updated_at=clock_timestamp() WHERE key='meta'");ok('additive install leaves legacy authority unchanged');
 await assert.rejects(tx(db,()=>transitionPlatformStore(db,'sql',initial,{actor:'test',checkpoint:()=>{throw Error('interrupted');}})),/interrupted/);
 assert.deepEqual(await readPlatformAuthority(db),initial);assert.equal((await db.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,0);ok('interrupted backfill rolls back rows and authority');
 const activated=await tx(db,()=>transitionPlatformStore(db,'sql',initial,{actor:'test'}));assert.equal(activated.counts.findings,1400);
 const loaded=await tx(db,()=>loadPlatformStore(db,activated.authority));assert.deepEqual(normalized(loaded.data),normalized(fixture));ok('all source payloads, metadata and fractional scores survive verified backfill');
 await assert.rejects(db.query("UPDATE vuln_store SET data=data WHERE key='meta'"),/stale|registered/);
 await assert.rejects(tx(db,()=>bindPlatformWriter(db,initial)),/authority changed/);ok('old and stale writers are fenced after cutover');
 let changed=structuredClone(loaded.data);changed.findings[0][1].status='Resolved';changed.findings.splice(2,1);changed.findings.push(['F-new',{id:'F-new',companyId:'CO-1',connector:'defender',status:'Open',future:{new:true}}]);changed.meta.sourceGenerations.defender='two';
 await assert.rejects(tx(db,()=>savePlatformStore(db,changed,loaded.state,{guard:()=>{throw Error('capture changed');}})),/capture changed/);
 assert.deepEqual((await tx(db,()=>loadPlatformStore(db,activated.authority))).data,loaded.data);ok('failed save preserves the complete prior generation');
 const saved=await tx(db,()=>savePlatformStore(db,changed,loaded.state));assert.deepEqual(saved.counts,{inserted:1,updated:1,deleted:1,metadata:1});
 assert.deepEqual(normalized((await tx(db,()=>loadPlatformStore(db,saved.authority))).data),normalized(changed));ok('incremental insert/update/delete commits one complete generation');
 const unchanged=await tx(db,()=>savePlatformStore(db,changed,saved));assert.deepEqual(unchanged.counts,{inserted:0,updated:0,deleted:0,metadata:0});assert.deepEqual(unchanged.authority,saved.authority);ok('unchanged restart flush does not rewrite records');
 await assert.rejects(tx(db,()=>savePlatformStore(db,loaded.data,loaded.state)),/authority changed/);ok('second process cannot overwrite a newer commit');
 // Hold a reader snapshot while a writer commits. It must see one generation.
 await other.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');const pinned=await readPlatformAuthority(other);
 changed.findings[0][1].status='In Remediation';const next=await tx(db,()=>savePlatformStore(db,changed,saved));
 assert.equal((await loadPlatformStore(other,pinned)).data.findings[0][1].status,'Resolved');await other.query('COMMIT');ok('concurrent hydration reads one committed MVCC generation');
 const reversed=await tx(db,()=>transitionPlatformStore(db,'legacy',next.authority,{actor:'test'}));assert.equal(reversed.authority.mode,'legacy');
 const actual={};for(const {key,data} of (await db.query('SELECT key,data FROM vuln_store ORDER BY key')).rows){if(key==='meta')Object.assign(actual,data);else{const kind=key.split(':')[0];(actual[kind]??=[]).push(...data);}}
 assert.equal(platformJson(normalized(actual)),platformJson(normalized(changed)));ok('reverse recovery includes post-cutover edits, inserts, deletes and metadata');
 await assert.rejects(tx(db,()=>savePlatformStore(db,changed,next)),/authority changed/);
 await assert.rejects(db.query("UPDATE vuln_store SET data=data WHERE key='meta'"),/stale|registered/);
 await tx(db,async()=>{await bindPlatformWriter(db,reversed.authority);await db.query("UPDATE vuln_store SET updated_at=clock_timestamp() WHERE key='meta'");});ok('reverse fences old processes while admitting the compatible writer');
 // Exercise the actual TypeScript persistence entry points and same-transaction
 // reporting publication, not only the standalone storage engine.
 for(const file of ['customer-reporting-inputs.sql','customer-reporting-buckets.sql','customer-reporting-sections.sql','customer-reporting-executive.sql'])await db.query(await readFile('docs/sql/'+file,'utf8'));
 const reporting=revisionModule.createReportingInputDigests();
 await tx(db,async()=>{await transitionPlatformStore(db,'sql',reversed.authority,{actor:'integration',reporting});await revisionModule.publishReportingInputRevisions(db,reporting.finish());});
 const nativePool=new pg.Pool({...config,database:name,max:2});
 const oldUrl=process.env.DATABASE_URL,oldMode=process.env.VULN_PLATFORM_STORE;process.env.DATABASE_URL='postgresql://localhost/test';process.env.VULN_PLATFORM_STORE='sql';
 try{
  const code=ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  async function instance(sameProcess=false){if(!sameProcess)delete globalThis.__vulnDatabasePersistenceV1;const m=new SourceTextModule(code);await m.link(name=>{
   const values=name==='pg'?{Pool:class{constructor(){return nativePool;}}}:name.endsWith('customer-reporting-revisions.mjs')?revisionModule:name.endsWith('platform-authority.mjs')?authorityModule:name.endsWith('platform-store.mjs')?storeModule:crypto;
   return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});});await m.evaluate();return m.namespace;}
  const runtime=await instance(),data=await runtime.loadSnapshot();
  const otherRoute=await instance(true);
  const before=await revisionModule.readReportingInputRevision(db,'CO-1');data.findings[0][1].severity='Critical';await otherRoute.saveSnapshot(data,{changes:{findings:[data.findings[0][0]]}});
  const shared=await readPlatformAuthority(db);await runtime.saveSnapshot(data,{changes:{}});assert.deepEqual(await readPlatformAuthority(db),shared);
  ok('separately bundled route modules share the loaded authority, committed hashes and later revisions');
  const after=await revisionModule.readReportingInputRevision(db,'CO-1');assert.notEqual(after.revision,before.revision);
  const complete=revisionModule.createReportingInputDigests();
  for(const [kind,c] of Object.entries(platformCollections))for(let b=0;b<c.buckets;b++)await complete.bucket(`${kind}:${String(b).padStart(2,'0')}`,JSON.stringify(data[kind].filter(([id])=>platformBucket(id,c.buckets)===b)));
  await complete.bucket('meta',JSON.stringify(Object.fromEntries(Object.entries(data).filter(([k])=>!platformCollections[k]))));
  assert.equal(complete.finish()[0].hash,after.hash,'Incremental reporting pieces must equal the independent full-generation digest');
  ok('bounded row edit publishes exactly the same reporting revision content as full comparison');
  const restarted=await instance();assert.equal((await restarted.loadSnapshot()).findings[0][1].severity,'Critical');
  const a=await readPlatformAuthority(db);await restarted.saveSnapshot(await restarted.loadSnapshot());assert.deepEqual(await readPlatformAuthority(db),a);
  process.env.VULN_PLATFORM_STORE='legacy';await assert.rejects((await instance()).loadSnapshot(),/requires VULN_PLATFORM_STORE/);
  ok('real persistence loads SQL, commits report revisions, survives restart and rejects a legacy-mode boot');
 }finally{await nativePool.end();if(oldUrl===undefined)delete process.env.DATABASE_URL;else process.env.DATABASE_URL=oldUrl;if(oldMode===undefined)delete process.env.VULN_PLATFORM_STORE;else process.env.VULN_PLATFORM_STORE=oldMode;}
 console.log(JSON.stringify({passed:checks}));
}finally{await other?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();}
