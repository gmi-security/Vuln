// Isolated Unix-socket PostgreSQL verification; never accepts a production URL.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import ts from 'typescript';
const socket=process.argv[2];
assert.ok(socket?.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'));
const settings={host:socket,port:55485,user:'codex'};
const admin=new pg.Client({...settings,database:'postgres'});await admin.connect();
assert.equal((await admin.query('SHOW listen_addresses')).rows[0].listen_addresses,'');
const name=`daily_schedule_${randomBytes(6).toString('hex')}`;
let db;
const require=createRequire(import.meta.url);
const day=86_400_000;
let clock=Math.floor(Date.now()/day)*day-3*day+4*3_600_000;
class ClockDate extends Date {
  constructor(...args){super(...(args.length?args:[clock]));}
  static now(){return clock;}
}
const scheduleCode=ts.transpileModule(await readFile('lib/connector-sync-schedule.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const schedule={exports:{}};
new Function('module','exports','Date',scheduleCode)(schedule,schedule.exports,ClockDate);
async function load(file,mocks) {
  const code=ts.transpileModule(await readFile(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
  const mod={exports:{}};new Function('require','module','exports','Date',code)(id=>id==='./connector-sync-schedule'?schedule.exports:mocks[id]??require(id),mod,mod.exports,ClockDate);return mod.exports;
}
try {
  await admin.query(`CREATE DATABASE ${name}`);db=new pg.Pool({...settings,database:name,max:4});
  await db.query('CREATE TABLE background_job_runs(job TEXT PRIMARY KEY,status TEXT,result JSONB,error TEXT,started_at TIMESTAMPTZ NOT NULL,finished_at TIMESTAMPTZ)');
  const jobs=await load('lib/background-job-runs.ts',{'./patch-ticket-store':{patchTicketDatabase:async()=>db}});
  clock--;assert.equal(await jobs.claimDailyJob('ticket-status-sync'),false);clock++;
  const attempts=await Promise.all(Array.from({length:12},()=>jobs.claimDailyJob('ticket-status-sync')));
  assert.equal(attempts.filter(Boolean).length,1);
  await jobs.recordJobRun('ticket-status-sync','failed',{},'fixture');
  assert.equal(await jobs.claimDailyJob('ticket-status-sync'),false);
  await db.query('UPDATE background_job_runs SET started_at=$1',[new Date(clock+60_000)]);
  clock+=day;
  assert.equal(await jobs.claimDailyJob('ticket-status-sync'),true);
  assert.equal(await jobs.claimDailyJob('risk-refresh'),true);
  const {createDefenderStore}=await load('lib/defender-store.ts',{
    './persist':{applicationDatabase:()=>db},
    './defender-client':{DefenderError:Error,sealDefender:JSON.stringify,openDefender:JSON.parse},
  });
  const store=createDefenderStore(db);
  await store.save({companyId:'TEST-A',tenantId:'tenant-a',clientId:'app-a',clientSecret:'fixture',daily:true},'test');
  await store.save({companyId:'TEST-B',tenantId:'tenant-b',clientId:'app-b',clientSecret:'fixture',daily:false},'test');
  await store.schedule();const first=await store.claim('TEST-A');assert.ok(first);assert.equal(await store.claim('TEST-B'),null);
  await store.fail(first.id,'fixture first attempt failed');
  await store.schedule();assert.equal(await store.claim('TEST-A'),null);
  await db.query("UPDATE defender_connections SET last_attempt_at=$1 WHERE company_id='TEST-A'",[new Date(clock+60_000)]);
  clock+=day;
  await store.schedule();const second=await store.claim('TEST-A');assert.ok(second);assert.notEqual(second.id,first.id);
  await store.fail(second.id,'fixture complete');
  clock-=1;
  assert.ok(await store.enqueue('TEST-A','sync-all'));
  const manual=await store.claim('TEST-A');assert.ok(manual);await store.fail(manual.id,'fixture manual completed');
  assert.equal(await jobs.claimDailyJob('daytime-new-job'),false);
  await db.query("UPDATE defender_connections SET last_attempt_at=NULL WHERE company_id='TEST-A'");
  await store.schedule();assert.equal(await store.claim('TEST-A'),null);
  console.log('PASS: nightly boundary, 12 concurrent claims, failed attempts, next calendar night without interval drift, independent jobs, Defender first import/retry, disabled customer and manual override');
}finally{
  if(db)await db.end();
  await admin.query(`DROP DATABASE IF EXISTS ${name}`);await admin.end();
}
