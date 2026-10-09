// Destructive fixtures are restricted to a disposable database on the private restore cluster.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
const require=createRequire(import.meta.url);
const {createSpotlightSummaryJobs:createJobs,SummaryLeaseLost}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-jobs.js');
const {createSpotlightSummaryStore:createStore}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-store.js');
const {createSpotlightSummaryWorker:createWorker}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-worker.js');
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const admin=new pg.Client({...options,database:'postgres'}),name=`vuln2_worker_test_${randomUUID().replaceAll('-','')}`;
let db,created=false,checks=0;const disconnected=[],children=[],ok=message=>{checks++;console.log(`PASS ${message}`);};
const sample=id=>({id,cid:'tenant',aid:'host',status:'open',cve:{id:'CVE-2026-1000',severity:'HIGH',base_score:8},suppression_info:{is_suppressed:false}});
function cli(company) {
  const url=`postgresql://codex@/${name}?host=${encodeURIComponent(socket)}&port=55483`;
  const child=spawn(process.execPath,['scripts/spotlight-summary-worker.mjs','--once'],{env:{...process.env,DATABASE_URL:url,VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED:'true',VULN_SPOTLIGHT_SUMMARY_CUSTOMERS:company},stdio:['ignore','pipe','pipe']});
  let output='';child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>output+=v);
  const done=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal,output}));});
  children.push({child,done});return {child,done};
}
try {
  await admin.connect();
  const isolation=(await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/')&&!isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Pool({...options,database:name,max:6});
  db.on('connect',client=>disconnected.push(new Promise(resolve=>client.once('end',resolve))));
  const jobs=createJobs(db),store=createStore(db),worker=createWorker(db);
  await assert.rejects(()=>worker.assertReady(),/migrations/);
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n,0);
  await db.query(`CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY,tenant_key text,status text,started_at timestamptz,finished_at timestamptz,checkpoint_version int,expected_count bigint,hydrated_count bigint);
    CREATE TABLE spotlight_import_current(tenant_key text PRIMARY KEY,run_id uuid);
    CREATE TABLE spotlight_import_records(run_id uuid,tenant_key text,company_id text,source_id text,cve text,status text,raw jsonb,PRIMARY KEY(run_id,tenant_key,source_id));`);
  for(const file of ['spotlight-source-summaries.sql','spotlight-summary-jobs.sql'])await db.query(await readFile(`docs/sql/${file}`,'utf8'));
  await worker.assertReady();ok('worker requires explicit migrations and never initializes the schema');
  async function install(company,raw=sample('1')) {
    const run=randomUUID();await db.query("INSERT INTO spotlight_import_runs VALUES($1,$2,'completed',now(),now(),3,1,1)",[run,company]);
    await db.query('INSERT INTO spotlight_import_records VALUES($1,$2,$2,$3,$4,$5,$6)',[run,company,raw.id,raw.cve.id,raw.status,raw]);
    await db.query('INSERT INTO spotlight_import_current VALUES($1,$2) ON CONFLICT(tenant_key) DO UPDATE SET run_id=EXCLUDED.run_id',[company,run]);return run;
  }
  const jobFor=async company=>(await jobs.list(company))[0];
  const due=company=>db.query("UPDATE spotlight_summary_jobs SET available_at=now()-interval '1 second' WHERE company_id=$1",[company]);
  const expire=company=>db.query("UPDATE spotlight_summary_jobs SET lease_until=now()-interval '1 second' WHERE company_id=$1 AND status='running'",[company]);
  await install('CO-A');await install('CO-B');
  assert.equal(await jobs.discover(['CO-A']),1);assert.equal(await jobs.discover(['CO-A']),0);
  assert.equal((await jobs.list('CO-B')).length,0);assert.equal(await jobs.claim(['CO-B']),null);
  const competing=await Promise.all([jobs.claim(['CO-A']),jobs.claim(['CO-A'])]);
  const first=competing.find(Boolean);assert.equal(competing.filter(Boolean).length,1);
  assert.equal(first.attempts,1);assert.equal('token' in (await jobFor('CO-A')),false);
  await jobs.heartbeat(first,1);assert.equal((await jobFor('CO-A')).sourceRows,'1');
  assert.equal(await jobs.finish(first,'busy'),true);assert.equal((await jobFor('CO-A')).attempts,0);
  await due('CO-A');assert.equal((await worker.tick(['CO-A'])).state,'succeeded');
  assert.equal((await jobFor('CO-A')).status,'succeeded');assert.equal((await worker.tick(['CO-A'])).state,'idle');
  ok('allowlist isolation, idempotent discovery, exclusive claims, safe status and busy deferral');
  await install('CO-RETRY');await jobs.discover(['CO-RETRY']);
  let retry=await jobs.claim(['CO-RETRY']);await expire('CO-RETRY');
  await assert.rejects(()=>jobs.heartbeat(retry,5),SummaryLeaseLost);assert.equal(await jobs.finish(retry,'succeeded'),false);
  assert.equal(await jobs.claim(['CO-RETRY']),null);assert.equal((await jobFor('CO-RETRY')).status,'retry');
  assert.equal((await jobFor('CO-RETRY')).errorCode,'lease-expired');
  let row=await jobFor('CO-RETRY');assert.ok(new Date(row.availableAt)-new Date(row.updatedAt)>=59000);
  await due('CO-RETRY');const second=await jobs.claim(['CO-RETRY']);assert.notEqual(first.token,second.token);assert.equal(second.attempts,2);
  assert.equal(await jobs.finish(retry,'succeeded'),false);await jobs.finish(second,'build-failed');
  row=await jobFor('CO-RETRY');assert.ok(new Date(row.availableAt)-new Date(row.updatedAt)>=299000);
  await due('CO-RETRY');retry=await jobs.claim(['CO-RETRY']);assert.equal(retry.attempts,3);await expire('CO-RETRY');
  assert.equal(await jobs.claim(['CO-RETRY']),null);assert.equal((await jobFor('CO-RETRY')).status,'failed');
  await jobs.discover(['CO-RETRY']);assert.equal((await jobFor('CO-RETRY')).status,'failed');
  ok('expired leases cannot be revived; retry delays are bounded and three failures stop automatic attempts');
  const old=await install('CO-SWAP');await jobs.discover(['CO-SWAP']);const newer=await install('CO-SWAP');
  await jobs.discover(['CO-SWAP']);assert.equal((await jobs.list('CO-SWAP')).find(v=>v.runId===old).status,'superseded');
  assert.equal((await store.build('CO-SWAP','tester',{expectedRunId:old})).state,'superseded');
  assert.equal((await worker.tick(['CO-SWAP'])).state,'succeeded');assert.equal((await jobFor('CO-SWAP')).runId,newer);
  ok('jobs remain bound to their import; superseded work cannot publish the wrong generation');
  const committed=await install('CO-ACK');await jobs.discover(['CO-ACK']);const unacknowledged=await jobs.claim(['CO-ACK']);
  assert.equal((await store.build('CO-ACK','tester',{expectedRunId:committed,beforePublish:client=>jobs.heartbeat(unacknowledged,1,client)})).state,'built');
  assert.equal((await jobFor('CO-ACK')).status,'running');
  assert.equal((await createWorker(db).tick(['CO-ACK'])).state,'idle');assert.equal((await jobFor('CO-ACK')).status,'succeeded');
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE company_id=$1',['CO-ACK'])).rows[0].n,1);
  ok('restart reconciles a committed summary before acknowledgement without rebuilding or duplicating it');
  const good=(await db.query("SELECT run_id FROM spotlight_summary_current WHERE company_id='CO-A'")).rows[0].run_id;
  const fenced=await install('CO-A');await jobs.discover(['CO-A']);const stale=await jobs.claim(['CO-A']);
  await assert.rejects(()=>store.build('CO-A','tester',{expectedRunId:fenced,beforePublish:async client=>{await expire('CO-A');await jobs.heartbeat(stale,1,client);}}),SummaryLeaseLost);
  assert.equal((await db.query("SELECT run_id FROM spotlight_summary_current WHERE company_id='CO-A'")).rows[0].run_id,good);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE run_id=$1',[fenced])).rows[0].n,0);
  ok('lease fencing inside publication rolls back incomplete rows and preserves the previous summary');
  await install('CO-BAD',{...sample('1'),aid:''});
  assert.equal((await worker.tick(['CO-BAD'])).state,'retry-or-failed');
  assert.equal((await jobFor('CO-BAD')).errorCode,'build-failed');assert.doesNotMatch(JSON.stringify(await jobs.list('CO-BAD')),/identity|tenant|raw/);
  ok('invalid source data becomes a bounded retry with a safe error code');
  const stopped=new AbortController();await install('CO-STOP');await jobs.discover(['CO-STOP']);const stopJob=await jobs.claim(['CO-STOP']);
  await assert.rejects(()=>store.build('CO-STOP','tester',{signal:stopped.signal,checkpoint:async()=>stopped.abort()}),/stopped/);
  await jobs.finish(stopJob,'worker-stopped');assert.equal((await jobFor('CO-STOP')).errorCode,'worker-stopped');
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_current WHERE company_id='CO-STOP'")).rows[0].n,0);
  ok('cooperative shutdown leaves retryable work and no partial publication');
  await install('CO-KILL');
  const hold=await db.connect();await hold.query('BEGIN');await hold.query('LOCK TABLE spotlight_import_records IN ACCESS EXCLUSIVE MODE');
  try {
    const running=cli('CO-KILL');let claimed=false;
    for(let i=0;i<30;i++){if((await jobFor('CO-KILL'))?.status==='running'){claimed=true;break;}await delay(50);}
    assert.ok(claimed,'child must claim before interruption');
    const competingCli=await cli('CO-KILL').done;assert.equal(competingCli.code,0);assert.match(competingCli.output,/already-running/);
    running.child.kill('SIGKILL');assert.equal((await running.done).signal,'SIGKILL');
    assert.equal((await jobFor('CO-KILL')).status,'running');
  } finally {await hold.query('ROLLBACK');hold.release();}
  await expire('CO-KILL');const recovery=await cli('CO-KILL').done;assert.equal(recovery.code,0);assert.equal((await jobFor('CO-KILL')).status,'retry');
  await due('CO-KILL');const recovered=await cli('CO-KILL').done;assert.equal(recovered.code,0);assert.match(recovered.output,/succeeded/);
  assert.equal((await jobFor('CO-KILL')).status,'succeeded');assert.equal((await jobFor('CO-KILL')).attempts,2);
  ok('actual killed process recovers on restart; a second CLI cannot overlap the first');
  console.log(JSON.stringify({passed:checks,productionChanges:0}));
} finally {
  for(const {child,done} of children){if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await done.catch(()=>{});}
  await db?.end();await Promise.all(disconnected);if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();
}
