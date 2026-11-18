// Isolated Unix-socket PostgreSQL only; never accepts production credentials.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import pg from 'pg';
import ts from 'typescript';
const socket=process.argv[2];
assert.ok(socket?.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const settings={host:socket,port:55483,user:'codex'};
const admin=new pg.Client({...settings,database:'postgres'});await admin.connect();
assert.equal((await admin.query('SHOW listen_addresses')).rows[0].listen_addresses,'');
const name=`sync_recovery_${randomBytes(6).toString('hex')}`;
const require=createRequire(import.meta.url),modules=new Map();
async function load(file) {
  if(modules.has(file))return modules.get(file);
  const source=await readFile(file,'utf8');
  const imports=[...source.matchAll(/from "(\.\/[^\"]+)"/g)].map(m=>m[1]);
  const dependencies={};
  for(const key of imports) dependencies[key]=key==='./patch-ticket-store'?{patchTicketDatabase:()=>assert.fail('must use isolated pool')}:await load(`lib/${key.slice(2)}.ts`);
  const code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
  const mod={exports:{}};new Function('require','module','exports',code)(id=>dependencies[id]??require(id),mod,mod.exports);
  modules.set(file,mod.exports);return mod.exports;
}
let db;
try {
  await admin.query(`CREATE DATABASE ${name}`);db=new pg.Pool({...settings,database:name,max:14});
  await db.query('CREATE TABLE background_job_runs(job TEXT PRIMARY KEY,status TEXT NOT NULL,result JSONB,error TEXT,started_at TIMESTAMPTZ NOT NULL,finished_at TIMESTAMPTZ)');
  const {acquireScheduledConnectorBatch:acquire,runConnectorSyncJobs:run}=await load('lib/connector-sync-batch.ts');
  const night=Date.parse('2026-11-18T04:00:00Z'),day=Date.parse('2026-11-18T20:00:00Z');
  assert.equal(await acquire(db,night-1),null);
  const contenders=await Promise.all(Array.from({length:12},()=>acquire(db,night)));
  const owners=contenders.filter(Boolean);assert.equal(owners.length,1);
  let owner=owners[0];
  const progress={version:1,nextStartAt:0,entries:[{connector:'Nessus',startedAt:night,result:{connector:'Nessus',configured:true,ok:true}}]};
  await owner.save(progress);await owner.release();
  owner=await acquire(db,day);assert.deepEqual(owner.progress,progress);assert.equal(owner.startedAt,'2026-11-18T04:00:00.000Z');
  let launches=0;
  await run([
    {connector:'Nessus',ready:true,run:async()=>assert.fail('duplicate')},
    {connector:'Spotlight',ready:true,run:async()=>{launches++;return {message:'started'};}},
  ],owner);await owner.release();assert.equal(launches,1);
  assert.equal((await db.query('SELECT status FROM background_job_runs')).rows[0].status,'succeeded');
  assert.equal(await acquire(db,day),null);assert.equal(await acquire(db,night+60_000),null);
  owner=await acquire(db,night+86_400_000);assert.ok(owner);await owner.release();

  // Simulate process death, rather than a cooperative release, and prove the next connection resumes.
  owner=await acquire(db,day+86_400_000);
  const lockPid=(await db.query("SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1713 AND objid=0 AND granted")).rows[0].pid;
  await db.query('SELECT pg_terminate_backend($1)',[lockPid]);
  await new Promise(resolve=>setTimeout(resolve,50));
  await assert.rejects(owner.save(progress),/lost its database lock/);await owner.release();
  owner=await acquire(db,day+86_400_000);assert.ok(owner);await owner.release();

  // Legacy rows use microsecond timestamps; ownership must compare the exact database value.
  await db.query("UPDATE background_job_runs SET result=NULL,status='running',started_at='2026-11-18T04:00:14.677143Z'");
  owner=await acquire(db,day);assert.equal(owner.progress,null);
  await owner.save(progress);await owner.release();
  assert.equal((await db.query("SELECT started_at::text AS at FROM background_job_runs")).rows[0].at,'2026-11-18 04:00:14.677143+00');

  // A concurrent/manual metadata replacement is fenced even with the same advisory connection.
  owner=await acquire(db,day);
  await db.query("UPDATE background_job_runs SET started_at=started_at+interval '1 second'");
  await assert.rejects(owner.save(progress),/ownership changed/);await owner.release();
  await db.query("UPDATE background_job_runs SET result='{\"version\":999}',status='running'");
  await assert.rejects(acquire(db,day),/Invalid saved connector progress/);
  await db.query("UPDATE background_job_runs SET result=NULL");
  owner=await acquire(db,day);assert.ok(owner);await owner.release();
  console.log('PASS: nightly/daytime gates, 12 concurrent claimants, persisted queue restart, completed batch dedupe, next night, killed owner recovery, lost-lock fencing, legacy microseconds, replaced ownership, malformed progress and lock cleanup');
} finally {
  if(db)await db.end();await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();
}
