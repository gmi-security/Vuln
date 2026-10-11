// Real private PostgreSQL, actual dedicated CLI and forced process interruption.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID,createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
import {createCustomerReportingWorker} from '../lib/db/customer-reporting-worker.mjs';
import {company,reportingFixture,expectedReport} from './reporting-sections-fixture.mjs';
globalThis.fetch=()=>{throw Error('No provider or ticket calls allowed');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const token=randomUUID().replaceAll('-',''),sourceName=`vuln2_reporting_source_test_${token}`,targetName=`vuln2_reporting_test_${token}`;
const admin=new pg.Client({...config,database:'postgres'}),children=[];let sourcePool,targetPool,created=[];let checks=0;
const ok=m=>{checks++;console.log('PASS '+m);};
const {create,reference}=await loadReportingSections();
const url=name=>{const u=new URL(`postgresql://codex@localhost/${name}`);u.searchParams.set('host',socket);u.searchParams.set('port','55483');return u.href;};
function cli(once=true,args=once?['--once']:[],customers=company.id){
 const child=spawn(process.execPath,['--max-old-space-size=512','scripts/customer-reporting-worker.mjs',...args],{
  env:{PATH:process.env.PATH,VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:customers,
   VULN_REPORTING_SOURCE_URL:url(sourceName),VULN_REPORTING_DATABASE_URL:url(targetName)},stdio:['ignore','pipe','pipe']});
 let output='';child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>output+=v);
 const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal,output}));});
 children.push(child);return {child,exited,get output(){return output;}};
}
async function waitFor(check){for(let i=0;i<150;i++){if(await check())return;await delay(100);}throw Error('Timed out waiting for fixture state');}
try{
 await admin.connect();const guard=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(guard.dir.startsWith('/home/codex/vuln-recovery/')&&!guard.listen);
 for(const name of [sourceName,targetName]){await admin.query(`CREATE DATABASE ${name}`);created.push(name);}
 sourcePool=new pg.Pool({...config,database:sourceName,max:3});targetPool=new pg.Pool({...config,database:targetName,max:4});
 await targetPool.query(await readFile('docs/sql/customer-reporting-sections.sql','utf8'));
 await targetPool.query(await readFile('docs/sql/customer-reporting-jobs.sql','utf8'));
 await sourcePool.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb,updated_at timestamptz DEFAULT now());CREATE TABLE vuln_metrics_history(id bigserial PRIMARY KEY,company_id text,ts timestamptz,data jsonb)');
 await sourcePool.query("INSERT INTO vuln_store(key,data) VALUES('meta','{}'),('companies:00',$1)",[JSON.stringify([[company.id,company]])]);
 const data=reportingFixture(1200);data.history=[];
 for(const [kind,n] of [['findings',64],['scans',8],['assets',16]]){
  const bucket=id=>createHash('sha1').update(id).digest().readUInt32BE(0)%n;data[kind].sort((a,b)=>bucket(a.id)-bucket(b.id));
  for(let i=0;i<n;i++)await sourcePool.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',
   [`${kind}:${String(i).padStart(2,'0')}`,JSON.stringify(data[kind].filter(r=>bucket(r.id)===i).map(r=>[r.id,r]))]);
 }
 const worker=createCustomerReportingWorker(sourcePool,targetPool,create);
 const jobRow=async()=>(await targetPool.query('SELECT * FROM customer_reporting_jobs WHERE company_id=$1',[company.id])).rows[0];
 const savedRow=async()=>(await targetPool.query('SELECT snapshot_id FROM customer_reporting_sections WHERE company_id=$1',[company.id])).rows[0];
 const read=async()=>{const s=await sourcePool.connect(),t=await targetPool.connect();try{return await readCustomerReportingSections(s,t,company.id);}finally{s.release();t.release();}};
 const change=()=>sourcePool.query("UPDATE vuln_store SET updated_at=clock_timestamp() WHERE key='scans:00'");
 await worker.assertReady();assert.equal(await worker.discover(company.id),1);assert.equal(await worker.discover(company.id),0);
 assert.equal((await jobRow()).requested_revision,1);assert.equal(await worker.claim(['OTHER']),null);
 const firstQueuedAt=(await jobRow()).requested_at.getTime();await change();await worker.discover(company.id);
 assert.equal((await jobRow()).requested_at.getTime(),firstQueuedAt);
 const first=await worker.claim([company.id]);assert.equal(await worker.claim([company.id]),null);
 assert.equal((await worker.run(first)).state,'succeeded');assert.equal((await jobRow()).state,'succeeded');
 assert.deepEqual((await read()).model,JSON.parse(JSON.stringify(expectedReport(reference,data))));
 assert.equal((await worker.tick([company.id])).state,'idle');
 ok('completed source discovery coalesces; one scoped claim atomically publishes a report and successful job');

 let intercept=true;
 const wrapped={query:(...args)=>targetPool.query(...args),async connect(){const client=await targetPool.connect();return {
  release:()=>client.release(),async query(sql,values){const result=await client.query(sql,values);
   if(intercept&&sql.startsWith('INSERT INTO customer_reporting_sections')){intercept=false;await change();await worker.discover(company.id);}return result;}};}};
 const racing=createCustomerReportingWorker(sourcePool,wrapped,create);await change();await worker.discover(company.id);
 const oldSnapshot=(await savedRow()).snapshot_id,next=await worker.claim([company.id]);
 await racing.run(next);assert.equal((await savedRow()).snapshot_id,oldSnapshot);assert.equal((await jobRow()).state,'queued');
 assert.equal((await worker.run(await worker.claim([company.id]))).state,'succeeded');
 ok('newer requested source revision fences an in-flight publication and retains the complete previous report');

 await change();await worker.discover(company.id);const expired=await worker.claim([company.id]);
 await targetPool.query("UPDATE customer_reporting_jobs SET lease_until=now()-interval '1 second' WHERE company_id=$1",[company.id]);
 const replacement=await worker.claim([company.id]);assert.notEqual(expired.token,replacement.token);
 await assert.rejects(()=>worker.heartbeat(expired),/lease lost/);assert.equal((await worker.run(expired)).state,'lease-lost');
 assert.equal((await jobRow()).lease_token,replacement.token);assert.equal((await worker.run(replacement)).state,'succeeded');
 ok('expired leases are reclaimed; an old worker cannot renew, acknowledge or replace a new claim');

 await change();await worker.discover(company.id);
 const broken=createCustomerReportingWorker(sourcePool,targetPool,()=>{throw Error('PRIVATE-ERROR-MUST-NOT-LEAK');});
 for(let i=1;i<=3;i++){
  await targetPool.query('UPDATE customer_reporting_jobs SET available_at=now() WHERE company_id=$1',[company.id]);
  const result=await broken.run(await worker.claim([company.id]));assert.doesNotMatch(JSON.stringify(result),/PRIVATE-ERROR/);
  assert.equal((await jobRow()).attempts,i);
 }
 assert.equal((await jobRow()).state,'failed');assert.equal(await worker.discover(company.id),0);assert.equal(await worker.claim([company.id]),null);
 const revision=(await jobRow()).requested_revision;
 await assert.rejects(()=>worker.retryFailed(company.id,revision-1),/job changed/);
 const requeued=await cli(true,['--retry-failed',company.id,String(revision)]).exited;
 assert.equal(requeued.code,0,requeued.output);assert.match(requeued.output,/"event":"requeued"/);assert.equal((await jobRow()).attempts,0);
 await assert.rejects(()=>worker.retryFailed(company.id,revision),/job changed/);
 await change();assert.equal(await worker.discover(company.id),1);assert.equal((await jobRow()).attempts,0);
 ok('three attempts cap retries; unchanged failure needs an explicit versioned retry or changed source');

 const stopped=new AbortController();stopped.abort();const prior=(await savedRow()).snapshot_id;
 assert.equal((await worker.run(await worker.claim([company.id]),stopped.signal)).state,'retry-or-superseded');
 assert.equal((await savedRow()).snapshot_id,prior);assert.equal((await jobRow()).last_error_code,'worker-stopped');
 await targetPool.query('UPDATE customer_reporting_jobs SET available_at=now()');await worker.run(await worker.claim([company.id]));
 await targetPool.query("UPDATE customer_reporting_sections SET expires_at=now()+interval '4 minutes'");
 assert.equal(await worker.discover(company.id),1);await worker.run(await worker.claim([company.id]));
 ok('shutdown preserves the prior report and unchanged sources refresh before report expiry');

 await change();const once=await cli().exited;assert.equal(once.code,0,once.output);assert.match(once.output,/"state":"succeeded"/);
 assert.equal((await read()).state,'available');ok('actual compiled dedicated CLI processes a queued refresh with no application hydration');
 const unavailable=await cli(true,['--once'],'CO-MISSING').exited;assert.equal(unavailable.code,1,unavailable.output);
 assert.match(unavailable.output,/"unavailable":1/);ok('one-shot execution reports unavailable customer discovery as a nonzero exit');

 // A disposable trigger makes the build observable long enough to kill the
 // process after claiming, while its report replacement is still uncommitted.
 await targetPool.query("CREATE FUNCTION pause_reporting_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(12); RETURN NEW; END; $$");
 await targetPool.query('CREATE TRIGGER pause_reporting_fixture BEFORE INSERT OR UPDATE ON customer_reporting_sections FOR EACH ROW EXECUTE FUNCTION pause_reporting_fixture()');
 await change();const beforeKill=(await savedRow()).snapshot_id,held=cli(false);
 await waitFor(async()=>{const {rows}=await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name='vuln-customer-reporting-worker' AND datname=$1 AND wait_event='PgSleep'",[targetName]);return rows.length>0;});
 const overlap=await cli().exited;assert.equal(overlap.code,0,overlap.output);assert.match(overlap.output,/already-running/);
 held.child.kill('SIGKILL');await held.exited;
 // PostgreSQL notices a lost client when the statement returns; wait for that
 // bounded statement to finish before removing the fixture trigger.
 await waitFor(async()=>{const {rows}=await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name='vuln-customer-reporting-worker' AND datname=$1",[targetName]);return rows.length===0;});
 assert.equal((await savedRow()).snapshot_id,beforeKill);assert.equal((await jobRow()).state,'running');
 await targetPool.query('DROP TRIGGER pause_reporting_fixture ON customer_reporting_sections');
 await targetPool.query("UPDATE customer_reporting_jobs SET lease_until=now()-interval '1 second'");
 const restarted=await cli().exited;assert.equal(restarted.code,0,restarted.output);assert.match(restarted.output,/"state":"succeeded"/);
 assert.notEqual((await savedRow()).snapshot_id,beforeKill);assert.equal((await jobRow()).state,'succeeded');
 ok('second CLI is excluded; killing the active process rolls back publication and restart recovers its expired job');

 const clean=cli(false);await waitFor(()=>clean.output.includes('"event":"tick"'));clean.child.kill('SIGTERM');
 const exit=await clean.exited;assert.equal(exit.code,0,exit.output);assert.match(exit.output,/"event":"stopped"/);
 ok('SIGTERM stops the polling worker cleanly and releases its ownership lock');
 console.log(`PASS ${checks} isolated reporting worker groups`);
}finally{
 for(const child of children)if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
 await Promise.allSettled([sourcePool?.end(),targetPool?.end()]);
 for(const name of created.reverse())await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();
}
