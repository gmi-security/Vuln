// Disposable private Unix-socket PostgreSQL only; never loads application env.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import * as crypto from 'node:crypto';
import * as authorityModule from '../lib/db/platform-authority.mjs';
import * as storeModule from '../lib/db/platform-store.mjs';
import * as readerModule from '../lib/db/platform-reader.mjs';
import * as publicationClientModule from '../lib/db/publication-client.mjs';
import * as revisionModule from '../lib/db/customer-reporting-revisions.mjs';
import {platformCollections,platformBucket,platformJson} from '../lib/db/platform-records.mjs';
import {readPlatformAuthority,bindPlatformWriter} from '../lib/db/platform-authority.mjs';
import {loadPlatformStore,preparePlatformDelta,commitPreparedPlatformStore,transitionPlatformStore} from '../lib/db/platform-store.mjs';
import {createReportingInputDigests,publishReportingInputRevisions,readReportingInputRevision} from '../lib/db/customer-reporting-revisions.mjs';

const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:60000};
const database='finding_generation_test_'+randomUUID().replaceAll('-','');
const admin=new pg.Client({...config,database:'postgres'});let db,reader,pool,created=false,checks=0;
const ok=label=>{checks++;console.log('PASS '+label);};
const tx=async(client,fn)=>{await client.query('BEGIN');try{const v=await fn();await client.query('COMMIT');return v;}catch(e){await client.query('ROLLBACK');throw e;}};
function buckets(data,kind){const c=platformCollections[kind],result=Array.from({length:c.buckets},()=>[]);for(const entry of data[kind])result[platformBucket(entry[0],c.buckets)].push(entry);return result;}
async function digests(data){const d=createReportingInputDigests();
 for(const kind of Object.keys(platformCollections))for(const [b,rows]of buckets(data,kind).entries())await d.bucket(`${kind}:${String(b).padStart(2,'0')}`,JSON.stringify(rows));
 await d.bucket('meta',JSON.stringify(Object.fromEntries(Object.entries(data).filter(([k])=>!platformCollections[k]))));return d.finish();}
try{
 await admin.connect();const guard=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
 await admin.query(`CREATE DATABASE ${database}`);created=true;
 db=new pg.Client({...config,database});reader=new pg.Client({...config,database});pool=new pg.Pool({...config,database,max:3});await db.connect();await reader.connect();
 const timed=await pool.connect(),timedOwner=publicationClientModule.trackPublicationClient(timed);
 await timed.query("BEGIN READ ONLY; SET LOCAL idle_in_transaction_session_timeout='250ms'");
 await new Promise(resolve=>setTimeout(resolve,700));
 assert.equal(timedOwner.firstError()?.code,'25P03');
 await assert.rejects(timed.query('SELECT 1'),/not queryable|terminated/);
 timedOwner.release();timedOwner.release();
 assert.equal((await pool.query('SELECT 1 n')).rows[0].n,1);
 ok('real idle disconnect between statements is contained and the next connection works');
 const size=Number(process.env.VULN_GENERATION_TEST_ROWS??3200);assert.ok(size>=3200&&size<=1500000);
 const fixture={companies:[['CO-1',{id:'CO-1',name:'One'}],['CO-2',{id:'CO-2',name:'Two'}]],scans:[],assets:[],folders:[],counter:1,meta:{defenderGenerations:{'CO-1':'old'}},
  findings:Array.from({length:size},(_,i)=>[`F-${String(i).padStart(8,'0')}`,{id:`F-${String(i).padStart(8,'0')}`,companyId:i%4?'CO-1':'CO-2',connector:i%4?'defender':'nessus',
   cve:`CVE-2026-${10000+i%10000}`,status:'Open',severity:'High',realRisk:44.5,remediation:'Synthetic patch instructions. '.repeat(12),defender:i%4?{runId:'old',active:true}:undefined}])};
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())');
 for(const kind of Object.keys(platformCollections))for(const [b,rows]of buckets(fixture,kind).entries())await db.query('INSERT INTO vuln_store VALUES($1,$2,now())',[`${kind}:${String(b).padStart(2,'0')}`,JSON.stringify(rows)]);
 await db.query("INSERT INTO vuln_store VALUES('meta',$1,now())",[JSON.stringify({counter:fixture.counter,meta:fixture.meta})]);
 for(const file of ['001_core_storage.sql','002_platform_store_authority.sql'])await tx(db,async()=>db.query(await readFile('db/migrations/'+file,'utf8')));
 const before=await readPlatformAuthority(db);await tx(db,()=>transitionPlatformStore(db,'sql',before,{actor:'generation-test'}));
 await db.query(await readFile('docs/sql/customer-reporting-inputs.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-reporting-buckets.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-reporting-sections.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-reporting-executive.sql','utf8'));
 await tx(db,async()=>publishReportingInputRevisions(db,await digests(fixture)));
 const oldAuthority=await readPlatformAuthority(db);
 const migrationStart=performance.now();await tx(db,async()=>db.query(await readFile('db/migrations/003_finding_generations.sql','utf8')));
 console.log(JSON.stringify({migrationMs:Math.round(performance.now()-migrationStart),rows:size}));
 const loaded=await tx(db,()=>loadPlatformStore(db,oldAuthority));
 fixture.findings=[];
 assert.equal(loaded.data.findings.length,size);assert.match(loaded.state.findingGeneration,/^00000000-/);
 assert.deepEqual(await readPlatformAuthority(db),oldAuthority);
 ok('generation migration preserves all records and current authority');
 const first=loaded.data.findings[0];first[1].status='In Remediation';
 let plan=await preparePlatformDelta({...loaded.data,findings:[first]},loaded.state,{findings:[first[0]]});
 const api=await import('../lib/db/platform-publication.mjs');
 const ordinaryReports=await api.preparePlatformReporting(pool,plan);
 const small=await tx(db,async()=>{const result=await commitPreparedPlatformStore(db,plan,{reportingPrepared:true});await publishReportingInputRevisions(db,ordinaryReports);return result;});
 assert.equal((await db.query('SELECT status FROM app_findings WHERE id=$1',[first[0]])).rows[0].status,'In Remediation');
 for(const d of await digests(loaded.data))assert.equal((await readReportingInputRevision(db,d.companyId)).hash,d.hash);
 ok('ordinary edits target the active physical generation');
 const base={data:loaded.data,state:small};
 // Restore reporting after the ordinary low-level writer test.
 await tx(db,async()=>publishReportingInputRevisions(db,await digests(base.data)));
 const updated=structuredClone(base.data),changed=[];
 for(let i=0;i<updated.findings.length;i++)if(updated.findings[i][1].companyId==='CO-1'){
  updated.findings[i][1].defender.runId='new';updated.findings[i][1].severity='Critical';changed.push(updated.findings[i][0]);
 }
 const removed=updated.findings.find(([id])=>id==='F-00000000');changed.push(removed[0]);updated.findings=updated.findings.filter(([id])=>id!==removed[0]);
 const moved=updated.findings.find(([id])=>id==='F-00000004');moved[1].companyId='CO-1';changed.push(moved[0]);
 updated.meta.defenderGenerations['CO-1']='new';
 plan=await preparePlatformDelta(updated,base.state,{findings:changed});
 const obsolete=randomUUID();
 await tx(db,async()=>{
  await bindPlatformWriter(db,base.state.authority);
  await db.query("INSERT INTO app_finding_publications(id,phase) VALUES($1,'published')",[obsolete]);
  await db.query('INSERT INTO app_finding_versions SELECT f.*, $1::uuid FROM app_findings f LIMIT 1000',[obsolete]);
 });
 let interrupted=false;
 await assert.rejects(api.prepareFindingPublication(pool,plan,{checkpoint:({phase})=>{if(phase==='writing'&&!interrupted){interrupted=true;throw Error('simulated process interruption');}}}),/simulated process interruption/);
 const journal=(await db.query("SELECT * FROM app_finding_publications WHERE phase='writing'")).rows[0];
 assert.equal(Number((await db.query('SELECT count(*) n FROM app_finding_versions WHERE generation=$1',[obsolete])).rows[0].n),0,'obsolete rows must be reclaimed before another large upload');
 assert.equal(journal.write_offset,500);assert.equal((await reader.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,size);
 assert.equal((await reader.query("SELECT payload->'meta'->'defenderGenerations'->>'CO-1' marker FROM app_store_metadata WHERE id=1")).rows[0].marker,'old');
 await assert.rejects(api.prepareFindingPublication(pool,plan,{checkpoint:({phase})=>{if(phase==='reporting')throw Error('report interrupted');}}),/report interrupted/);
 const progress=(await db.query('SELECT report_progress FROM app_finding_publications WHERE id=$1',[journal.id])).rows[0].report_progress;
 assert.ok(Object.keys(progress).length>0);
 const stageStart=performance.now();let staged=await api.prepareFindingPublication(pool,plan);
 assert.equal(staged.id,journal.id);assert.equal(staged.record_count,size-1);
 console.log(JSON.stringify({stageMs:Math.round(performance.now()-stageStart),changed:changed.length,rows:size}));
 assert.equal((await reader.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,size);
 ok('interrupted private upload resumes its durable batch without exposing incomplete findings');
 // A restarted first import can recreate its folder/metadata. Reuse frozen
 // finding progress, but recompute reporting for the new small-record plan.
 updated.folders=[['FO-1',{id:'FO-1',companyId:'CO-1',name:'Defender',createdAt:'2026-10-28T12:00:00Z'}]];
 plan=await preparePlatformDelta(updated,base.state,{findings:changed,folders:['FO-1']});
 const oldReportHash=staged.report_plan_hash;
 staged=await api.prepareFindingPublication(pool,plan,{checkpoint:({phase})=>assert.equal(phase,'reporting')});
 assert.equal(staged.id,journal.id);assert.notEqual(staged.report_plan_hash,oldReportHash);
 ok('restarted first-import metadata changes reuse findings and rebuild reporting');
 if(size===3200){
  const item=updated.findings.find(([id])=>id===changed[0]);item[1].title='different pending plan';
  const alternate=await preparePlatformDelta(updated,base.state,{findings:changed,folders:['FO-1']});delete item[1].title;
  await assert.rejects(api.prepareFindingPublication(pool,alternate,{checkpoint:({phase})=>{if(phase==='writing')throw Error('alternate interrupted');}}),/alternate interrupted/);
  staged=await api.prepareFindingPublication(pool,plan);
  assert.notEqual(staged.id,journal.id);
  ok('returning to an older abandoned plan starts a clean generation instead of blocking saves');
 }
 await reader.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 assert.equal((await reader.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,size);
 await assert.rejects(tx(db,async()=>{await commitPreparedPlatformStore(db,plan,{publication:staged});await publishReportingInputRevisions(db,staged.report_digests);throw Error('final rollback');}),/final rollback/);
 assert.deepEqual(await readPlatformAuthority(db),base.state.authority);
 const finalStart=performance.now();const committed=await tx(db,async()=>{const result=await commitPreparedPlatformStore(db,plan,{publication:staged});await publishReportingInputRevisions(db,staged.report_digests);return result;});
 console.log(JSON.stringify({finalCommitMs:Math.round(performance.now()-finalStart)}));
 assert.equal((await reader.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,size);await reader.query('COMMIT');
 assert.equal((await reader.query('SELECT count(*)::int n FROM app_findings')).rows[0].n,size-1);
 updated.findings=[];loaded.data.findings=[];
 const restarted=await tx(db,()=>loadPlatformStore(db,committed.authority));
 assert.equal(restarted.state.findingGeneration,staged.id);
 assert.equal(restarted.data.meta.defenderGenerations['CO-1'],'new');
 for(const d of await digests(restarted.data))assert.equal((await readReportingInputRevision(db,d.companyId)).hash,d.hash);
 ok('final rollback, atomic visibility, restart and independent customer reporting hashes agree');
 await assert.rejects(api.prepareFindingPublication(pool,plan),/authority changed/);
 ok('stale plans cannot stage or publish over a newer writer');
 if(size===3200){
  let failPrivate=true,losePrivate=true,loseCommit=false,idleFinal=false,liveCommits=0;
  const observedPool={on(){},query:(...args)=>pool.query(...args),async connect(){
   const c=await pool.connect();let live=false,privateWrite=false;
   return {on:(...a)=>c.on(...a),once:(...a)=>c.once(...a),off:(...a)=>c.off(...a),release:e=>c.release(e),async query(sql,params){
    const result=await c.query(sql,params);
    if(idleFinal&&sql.startsWith('BEGIN;')&&sql.includes("lock_timeout='10s'")){
     idleFinal=false;await c.query("SET LOCAL idle_in_transaction_session_timeout='250ms'");
     await new Promise(resolve=>setTimeout(resolve,700));
    }
    if(sql.startsWith('INSERT INTO app_finding_versions'))privateWrite=true;
    if(sql.startsWith('INSERT INTO app_finding_versions')&&failPrivate){failPrivate=false;throw Object.assign(Error('private cancellation'),{code:'57014'});}
    if(sql.startsWith('UPDATE app_finding_head')||sql.startsWith('UPDATE app_store_authority'))live=true;
    if(sql==='COMMIT'&&live){liveCommits++;if(loseCommit){loseCommit=false;throw Object.assign(Error('lost final commit acknowledgement'),{code:'08006'});}}
    if(sql==='COMMIT'&&privateWrite&&losePrivate){
     losePrivate=false;
     assert.equal((await readPlatformAuthority(db)).revision,committed.authority.revision);
     assert.equal((await db.query("SELECT write_offset FROM app_finding_publications WHERE phase='writing'")).rows[0].write_offset,500);
     throw Object.assign(Error('lost private commit acknowledgement'),{code:'08006'});
    }
    if(sql==='COMMIT'||sql==='ROLLBACK')privateWrite=false;
    return result;
   }};
  }};
  const oldEnv={url:process.env.DATABASE_URL,mode:process.env.VULN_PLATFORM_STORE,role:process.env.VULN_RUNTIME_ROLE};
  process.env.DATABASE_URL='postgresql://localhost/private-test';process.env.VULN_PLATFORM_STORE='sql';process.env.VULN_RUNTIME_ROLE='worker';
  try{
   const code=ts.transpileModule(await readFile('lib/persist.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
   const instance=async()=>{delete globalThis.__vulnDatabasePersistenceV1;const m=new SourceTextModule(code);await m.link(name=>{
    const values=name==='pg'?{Pool:class{constructor(){return observedPool;}}}:name.endsWith('publication-client.mjs')?publicationClientModule:name.endsWith('customer-reporting-revisions.mjs')?revisionModule:name.endsWith('platform-authority.mjs')?authorityModule:name.endsWith('platform-store.mjs')?storeModule:name.endsWith('platform-reader.mjs')?readerModule:crypto;
    return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});});await m.evaluate();return m.namespace;};
   let runtime=await instance(),data=await runtime.loadSnapshot();
   const extra=Array.from({length:10001},(_,i)=>[`N-${i}`,{id:`N-${i}`,companyId:'CO-1',connector:'defender',status:'Open',severity:'High'}]);
   data.findings.push(...extra);data.meta.defenderGenerations['CO-1']='runtime-import';
   const options={changes:{findings:extra.map(([id])=>id)}};
   await runtime.saveSnapshot(data,options);
   assert.equal(liveCommits,1);
   for(const d of await digests(data))assert.equal((await readReportingInputRevision(db,d.companyId)).hash,d.hash);
   ok('actual persistence entrypoint resumes a private failure and commits matching reporting');
   const beforeIdle=await readPlatformAuthority(db);idleFinal=true;data.counter++;
   await assert.rejects(runtime.saveSnapshot(data,{changes:{}}),e=>e.code==='25P03');
   assert.equal(liveCommits,1,'final transaction disconnect must not be replayed');
   assert.deepEqual(await readPlatformAuthority(db),beforeIdle);
   ok('real final-transaction idle disconnect preserves SQLSTATE and never retries');
   for(const [,row]of extra)row.severity='Critical';data.counter++;loseCommit=true;
   await assert.rejects(runtime.saveSnapshot(data,options),e=>e.code==='08006');
   const afterUnknown=await readPlatformAuthority(db);
   await assert.rejects(runtime.saveSnapshot(data,{changes:{}}),/authority changed/);
   assert.deepEqual(await readPlatformAuthority(db),afterUnknown);
   runtime=await instance();data=await runtime.loadSnapshot();data.counter++;
   await runtime.saveSnapshot(data,{changes:{}});
   ok('lost final acknowledgement is not replayed; restart recovers and ordinary saves continue');
   const beforeReverse=await readPlatformAuthority(db);
   const legacy=await tx(db,()=>transitionPlatformStore(db,'legacy',beforeReverse,{actor:'generation-recovery-test'}));
   const back=await tx(db,()=>transitionPlatformStore(db,'sql',legacy.authority,{actor:'generation-recovery-test'}));
   const restored=await tx(db,()=>loadPlatformStore(db,back.authority));
   assert.equal(restored.data.findings.length,data.findings.length);
   assert.deepEqual(await digests(restored.data),await digests(data));
   assert.equal(restored.data.counter,data.counter);
   ok('forward and reverse maintenance transitions retain generation-backed findings and metadata');
  }finally{
   for(const[k,v]of Object.entries({DATABASE_URL:oldEnv.url,VULN_PLATFORM_STORE:oldEnv.mode,VULN_RUNTIME_ROLE:oldEnv.role}))if(v===undefined)delete process.env[k];else process.env[k]=v;
   delete globalThis.__vulnDatabasePersistenceV1;
  }
 }
 console.log(JSON.stringify({passed:checks}));
}finally{await pool?.end();await reader?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${database} WITH(FORCE)`);await admin.end();}
