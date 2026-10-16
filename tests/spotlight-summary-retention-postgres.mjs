import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import pg from 'pg';
const require=createRequire(import.meta.url);
const {createSpotlightSummaryRetention:create}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-retention.js');
const {createSpotlightSummaryStore:createStore}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-store.js');
const {createSpotlightSummaryAccumulator,SPOTLIGHT_SUMMARY_VERSION}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-model.js');
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const admin=new pg.Client({...options,database:'postgres'}),name=`vuln2_retention_test_${randomUUID().replaceAll('-','')}`;
let db,created=false,checks=0;const disconnected=[],ok=message=>{checks++;console.log(`PASS ${message}`);};
try {
  await admin.connect();
  const isolation=(await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/')&&!isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Pool({...options,database:name,max:6});
  db.on('connect',client=>disconnected.push(new Promise(resolve=>client.once('end',resolve))));
  const service=create(db);
  await assert.rejects(()=>service.run('CO-A'),e=>e.code==='42P01');
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n,0);
  await db.query(`CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY,tenant_key text,status text,started_at timestamptz,finished_at timestamptz,checkpoint_version int,expected_count bigint,hydrated_count bigint);
    CREATE TABLE spotlight_import_current(tenant_key text PRIMARY KEY,run_id uuid);
    CREATE TABLE spotlight_import_records(run_id uuid,raw jsonb);
    CREATE TABLE dashboard_daily_history(value text);INSERT INTO dashboard_daily_history VALUES('preserve history');
    CREATE TABLE patch_ticket_requests(value text);INSERT INTO patch_ticket_requests VALUES('preserve ticket');
    CREATE TABLE elastic_dashboard_queries(value text);INSERT INTO elastic_dashboard_queries VALUES('preserve tile');`);
  for(const file of ['spotlight-source-summaries.sql','spotlight-summary-jobs.sql'])await db.query(await readFile(`docs/sql/${file}`,'utf8'));
  async function install(company,n,age=100,version=1){
    const result=[];
    const a=createSpotlightSummaryAccumulator(company);
    a.add({source_id:'1',id:'1',company_id:company,cve:'CVE-2026-1000',status:'open',cid:'tenant',aid:'host',raw_cve:'CVE-2026-1000',raw_status:'open',raw_severity:'HIGH',score:7.5,suppressed:false});
    const summary=a.finish().summary;
    for(let i=0;i<n;i++){
      const run=randomUUID();result.push(run);
      await db.query("INSERT INTO spotlight_import_runs VALUES($1,$2,'completed',now(),now(),3,1,1)",[run,company]);
      await db.query('INSERT INTO spotlight_import_records VALUES($1,$2)',[run,{keep:true}]);
      await db.query(`INSERT INTO spotlight_summary_generations(company_id,run_id,model_version,source_completed_at,source_rows,count_verification,summary,cve_count,built_at,built_by)
        VALUES($1,$2,$6,now(),1,'import-count-reconciled',$3,1,now()-make_interval(days=>$4,secs=>$5),'tester')`,[company,run,summary,age,i,version]);
      await db.query("INSERT INTO spotlight_summary_cves(company_id,run_id,model_version,cve,severity,cvss,affected_devices,source_instances) VALUES($1,$2,$3,'CVE-2026-1000','HIGH',7.5,1,1)",[company,run,version]);
    }
    await db.query('INSERT INTO spotlight_import_current VALUES($1,$2)',[company,result[0]]);
    await db.query('INSERT INTO spotlight_summary_current VALUES($1,$2,$3)',[company,result[0],version]);
    return result;
  }
  const ids=await install('CO-A',8),other=await install('CO-B',8);
  await db.query("UPDATE spotlight_summary_current SET run_id=$1 WHERE company_id='CO-A'",[ids[7]]);
  await db.query("UPDATE spotlight_import_current SET run_id=$1 WHERE tenant_key='CO-A'",[ids[6]]);
  // Even an expired running job remains protected until normal job recovery resolves it.
  await db.query("INSERT INTO spotlight_summary_jobs(company_id,run_id,model_version,status,attempts,lease_token,lease_until) VALUES('CO-A',$1,1,'running',1,$2,now()-interval '1 minute')",[ids[5],randomUUID()]);
  await db.query("INSERT INTO spotlight_summary_jobs(company_id,run_id,model_version,status,finished_at) VALUES('CO-A',$1,1,'succeeded',now()-interval '400 days')",[ids[4]]);
  const policy={keepRecent:3,maxAgeDays:30,batchSize:1};
  const preview=await service.run('CO-A',{policy});
  assert.equal(preview.state,'preview');assert.deepEqual(preview.generations.map(v=>v.runId),[ids[4]]);
  assert.equal(preview.moreCandidates,true);assert.equal(preview.jobs.length,0);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations')).rows[0].n,16);
  ok('read-only preview is bounded and protects current, source-current, newest three and active work');
  const held=await db.connect();await held.query('SELECT pg_advisory_lock(804244,1)');
  assert.equal((await service.run('CO-A',{apply:true,policy})).state,'busy');
  await held.query('SELECT pg_advisory_unlock(804244,1)');held.release();
  ok('cleanup defers when a builder owns the publication lock');
  // Revalidation must not honor an old preview after its candidate becomes current.
  await db.query("UPDATE spotlight_summary_current SET run_id=$1 WHERE company_id='CO-A'",[ids[4]]);
  const applied=await service.run('CO-A',{apply:true,policy});assert.notEqual(applied.generations[0].runId,ids[4]);
  await db.query("UPDATE spotlight_summary_current SET run_id=$1 WHERE company_id='CO-A'",[ids[0]]);
  await service.run('CO-A',{apply:true,policy});await service.run('CO-A',{apply:true,policy});
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE run_id=$1',[ids[4]])).rows[0].n,0);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_cves WHERE run_id=$1',[ids[4]])).rows[0].n,0);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_jobs WHERE run_id=$1',[ids[4]])).rows[0].n,0);
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_generations WHERE company_id='CO-B'")).rows[0].n,other.length);
  ok('apply reselects candidates, cascades only their CVE details, and retires old terminal jobs on a later pass');
  const rollback=await install('CO-ROLLBACK',6);
  await db.query(`CREATE FUNCTION reject_retention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture delete failure'; END $$;
    CREATE TRIGGER reject_retention BEFORE DELETE ON spotlight_summary_generations FOR EACH ROW WHEN (OLD.run_id='${rollback[4]}') EXECUTE FUNCTION reject_retention()`);
  await assert.rejects(()=>service.run('CO-ROLLBACK',{apply:true,policy:{keepRecent:3,maxAgeDays:30}}),/fixture delete failure/);
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_generations WHERE company_id='CO-ROLLBACK'")).rows[0].n,6);
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_cves WHERE company_id='CO-ROLLBACK'")).rows[0].n,6);
  await db.query('DROP TRIGGER reject_retention ON spotlight_summary_generations;DROP FUNCTION reject_retention()');
  ok('an interrupted batch rolls back previously deleted headers and child rows');
  const readIds=await install('CO-READER',5,100,SPOTLIGHT_SUMMARY_VERSION);
  await db.query("UPDATE spotlight_summary_current SET run_id=$1 WHERE company_id='CO-READER'",[readIds[4]]);
  let pruned=false;
  const reader=createStore({connect:async()=>{
    const client=await db.connect();return {release:v=>client.release(v),query:async(sql,args)=>{
      const response=await client.query(sql,args);
      if(sql.includes('FROM public.spotlight_summary_current p')){
        await db.query("UPDATE spotlight_summary_current SET run_id=$1 WHERE company_id='CO-READER'",[readIds[0]]);
        const result=await service.run('CO-READER',{apply:true,policy});assert.equal(result.generations[0].runId,readIds[4]);pruned=true;
      }
      return response;
    }};
  }});
  const read=await reader.read({companyId:'CO-READER',now:new Date(),staleAfterMs:86400000});
  assert.equal(pruned,true);assert.equal(read.state,'available');assert.equal(read.generation.id,readIds[4]);assert.equal(read.cves.rows.length,1);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE run_id=$1',[readIds[4]])).rows[0].n,0);
  ok('an in-flight real summary reader retains its complete snapshot after promotion and pruning');
  await install('CO-COUNT',94,0);
  const cap=await service.run('CO-COUNT');assert.equal(cap.generations.length,4);
  await service.run('CO-COUNT',{apply:true});assert.equal((await service.run('CO-COUNT')).generations.length,0);
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_generations WHERE company_id='CO-COUNT'")).rows[0].n,90);
  ok('the count cap works for frequent recent imports without waiting for the age cutoff');
  const age=await install('CO-AGE',5,400);await service.run('CO-AGE',{apply:true});
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_generations WHERE company_id='CO-AGE'")).rows[0].n,3);
  for(let i=0;i<103;i++)await db.query("INSERT INTO spotlight_summary_jobs(company_id,run_id,model_version,status,finished_at) VALUES('CO-JOBS',$1,1,'failed',now()-make_interval(secs=>$2))",[randomUUID(),i]);
  assert.equal((await service.run('CO-JOBS')).jobs.length,3);await service.run('CO-JOBS',{apply:true});
  const sourceRun=randomUUID();await db.query("INSERT INTO spotlight_import_current VALUES('CO-JOBS',$1)",[sourceRun]);
  await db.query("INSERT INTO spotlight_summary_jobs(company_id,run_id,model_version,status,finished_at) VALUES('CO-JOBS',$1,1,'failed',now()-interval '400 days')",[sourceRun]);
  assert.ok(!(await service.run('CO-JOBS')).jobs.some(v=>v.runId===sourceRun));
  await db.query(`INSERT INTO spotlight_summary_jobs(company_id,run_id,model_version,status,finished_at)
    SELECT 'CO-BATCH',gen_random_uuid(),1,'superseded',now()-interval '400 days' FROM generate_series(1,201)`);
  const batch=await service.run('CO-BATCH');assert.equal(batch.jobs.length,100);assert.equal(batch.moreCandidates,true);
  await service.run('CO-BATCH',{apply:true});
  assert.equal((await db.query("SELECT count(*)::int n FROM spotlight_summary_jobs WHERE company_id='CO-BATCH'")).rows[0].n,101);
  ok('age expiry retains rollback summaries; job caps never erase current-import failures');
  const expected=8+8+6+5+94+5;
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_import_runs')).rows[0].n,expected);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_import_records')).rows[0].n,expected);
  for(const table of ['dashboard_daily_history','patch_ticket_requests','elastic_dashboard_queries'])assert.equal((await db.query(`SELECT count(*)::int n FROM ${table}`)).rows[0].n,1);
  ok('raw imports, daily history, ticket and saved-tile fixtures remain untouched');
  console.log(JSON.stringify({passed:checks,productionChanges:0}));
} finally {
  await db?.end();await Promise.all(disconnected);if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();
}
