// Explicit, isolated restore audit. Uses the prior independent batch baseline;
// installs/removes only the four new summary/job tables, never retained source data.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import pg from 'pg';
const require=createRequire(import.meta.url);
const {createSpotlightSummaryStore}=require('../.worker-build/spotlight-summary/lib/spotlight-summary-store.js');
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const db=new pg.Pool({host:socket,port:55483,user:'codex',database:'recovery_application',max:2,connectionTimeoutMillis:5000,statement_timeout:15000});
let summaryInstalled=false,jobsInstalled=false,child;
const tables=['spotlight_summary_jobs','spotlight_summary_current','spotlight_summary_cves','spotlight_summary_generations'];
async function once(companyId){
  const url=`postgresql://codex@/recovery_application?host=${encodeURIComponent(socket)}&port=55483`;
  child=spawn(process.execPath,['--max-old-space-size=512','scripts/spotlight-summary-worker.mjs','--once'],{env:{...process.env,DATABASE_URL:url,VULN_SPOTLIGHT_SUMMARY_WORKER_ENABLED:'true',VULN_SPOTLIGHT_SUMMARY_CUSTOMERS:companyId},stdio:['ignore','pipe','pipe']});
  let output='';child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>output+=v);
  const done=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>resolve(code));});
  const code=await done;child=undefined;assert.equal(code,0,output);return output;
}
try {
  const check=(await db.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(check.data.startsWith('/home/codex/vuln-recovery/')&&!check.listen);
  for(const table of tables)assert.equal((await db.query('SELECT to_regclass($1) AS name',[`public.${table}`])).rows[0].name,null,'Never overwrite an existing table');
  const baselines=JSON.parse(await readFile('spotlight-summary-baseline.json','utf8'));assert.ok(baselines.length);
  await db.query(await readFile('docs/sql/spotlight-source-summaries.sql','utf8'));summaryInstalled=true;
  await db.query(await readFile('docs/sql/spotlight-summary-jobs.sql','utf8'));jobsInstalled=true;
  for(const baseline of baselines){
    const pointer=(await db.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[baseline.companyId])).rows[0];
    assert.equal(pointer.run_id,baseline.runId);
    const start=performance.now();const output=await once(baseline.companyId);assert.match(output,/"state":"succeeded"/);
    const elapsedMs=Math.round(performance.now()-start);
    const job=(await db.query('SELECT * FROM spotlight_summary_jobs WHERE company_id=$1',[baseline.companyId])).rows[0];
    assert.equal(job.status,'succeeded');assert.equal(job.attempts,1);assert.equal(Number(job.source_rows),baseline.sourceRows);
    const header=(await db.query('SELECT * FROM spotlight_summary_generations WHERE company_id=$1',[baseline.companyId])).rows[0];
    assert.deepEqual(header.summary,baseline.summary);assert.equal(Number(header.source_rows),baseline.sourceRows);
    const all=(await db.query(`SELECT cve,severity,cvss,affected_devices,source_instances FROM spotlight_summary_cves
      WHERE company_id=$1 AND run_id=$2 AND model_version=1 ORDER BY severity_rank DESC,affected_devices DESC,cve`,[baseline.companyId,baseline.runId])).rows;
    assert.deepEqual(all.map(v=>({cve:v.cve,severity:v.severity,cvss:v.cvss,affectedDevices:Number(v.affected_devices),sourceInstances:Number(v.source_instances)})),baseline.cves);
    const reader=createSpotlightSummaryStore(db),timings=[];
    for(let i=0;i<3;i++){
      const at=performance.now();const read=await reader.read({companyId:baseline.companyId,now:new Date(),staleAfterMs:86400000,limit:100});
      timings.push(Math.round((performance.now()-at)*10)/10);assert.equal(read.state,'available');assert.equal(read.projection.state,'ready');assert.deepEqual(read.summary,baseline.summary);
    }
    assert.match(await once(baseline.companyId),/"state":"idle"/);
    assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_jobs WHERE company_id=$1',[baseline.companyId])).rows[0].n,1);
    console.log(JSON.stringify({companyId:baseline.companyId,sourceRows:baseline.sourceRows,allCvesMatched:all.length,workerElapsedMs:elapsedMs,savedReadMs:timings,attempts:job.attempts,restart:'idle-no-new-job',productionChanges:0}));
  }
} finally {
  if(child){const closed=new Promise(resolve=>child.once('close',resolve));child.kill('SIGKILL');await closed;}
  if(jobsInstalled)await db.query('DROP TABLE spotlight_summary_jobs');
  if(summaryInstalled)await db.query('DROP TABLE spotlight_summary_current,spotlight_summary_cves,spotlight_summary_generations');
  await db.end();
}
