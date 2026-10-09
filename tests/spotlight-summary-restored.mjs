// Explicit validation on the private restore only. Adds/removes only the three
// new summary tables; never changes retained source imports, credentials or tickets.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import pg from 'pg';
import {loadSpotlightSummaryModules} from '../scripts/source-read-model-loader.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const db=new pg.Pool({host:socket,port:55483,user:'codex',database:'recovery_application',max:3,connectionTimeoutMillis:5000,statement_timeout:15000});
const {createSpotlightSummaryStore:create}=await loadSpotlightSummaryModules();
let installed=false;
try {
  const check=(await db.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(check.data.startsWith('/home/codex/vuln-recovery/')&&!check.listen);
  const tables=['spotlight_summary_current','spotlight_summary_cves','spotlight_summary_generations'];
  for(const table of tables)assert.equal((await db.query('SELECT to_regclass($1) AS name',[`public.${table}`])).rows[0].name,null,'Do not overwrite existing tables');
  const baselines=JSON.parse(await readFile('spotlight-summary-baseline.json','utf8'));assert.ok(baselines.length);
  await db.query(await readFile('docs/sql/spotlight-source-summaries.sql','utf8'));installed=true;
  let building=false,reads=0;
  const service=create({connect:async()=>{
    const client=await db.connect();
    return{release:v=>client.release(v),query:async(sql,args)=>{
      if(/^(INSERT|UPDATE|DELETE)/.test(sql))assert.ok(sql.startsWith('INSERT INTO public.spotlight_summary_'),'Only summary table writes allowed');
      if(sql.includes('spotlight_import_records')){assert.ok(building,'Saved reader/replay must not touch raw records');reads++;}
      const result=await client.query(sql,args);
      if(building&&sql.includes('ORDER BY r.source_id')&&reads%100===0)console.log(JSON.stringify({phase:'summary-build',sourceBatches:reads-1}));
      return result;
    }};
  }});
  for(const baseline of baselines){
    const pointer=(await db.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[baseline.companyId])).rows[0];
    assert.equal(pointer.run_id,baseline.runId,'Baseline must match the retained generation');
    const request={companyId:baseline.companyId,now:new Date(),staleAfterMs:86400000,limit:100};
    assert.equal((await service.read(request)).state,'summary-pending');
    building=true;const built=await service.build(baseline.companyId,'private-restored-parity');building=false;
    assert.equal(built.state,'built');assert.equal(built.sourceRows,baseline.sourceRows);
    const timings=[];
    for(let i=0;i<5;i++){
      const start=performance.now(),result=await service.read(request);timings.push(Math.round((performance.now()-start)*10)/10);
      assert.equal(result.state,'available');assert.equal(result.projection.state,'ready');
      assert.deepEqual(result.summary,baseline.summary);assert.deepEqual(result.cves.rows,baseline.cves.slice(0,100));
    }
    for(const offset of [100,Math.max(0,baseline.cves.length-50),baseline.cves.length+1]){
      const result=await service.read({...request,offset});assert.deepEqual(result.cves.rows,baseline.cves.slice(offset,offset+100));
      assert.equal(result.cves.total,baseline.cves.length);
    }
    const all=(await db.query(`SELECT cve,severity,cvss,affected_devices,source_instances FROM spotlight_summary_cves
      WHERE company_id=$1 AND run_id=$2 AND model_version=1 ORDER BY severity_rank DESC,affected_devices DESC,cve`,[baseline.companyId,baseline.runId])).rows;
    assert.deepEqual(all.map(row=>({cve:row.cve,severity:row.severity,cvss:row.cvss,sourceInstances:Number(row.source_instances),affectedDevices:Number(row.affected_devices)})),baseline.cves);
    const start=performance.now(),replayed=await service.build(baseline.companyId,'private-restored-parity');
    assert.equal(replayed.state,'reused');const replayMs=Math.round((performance.now()-start)*10)/10;
    assert.equal((await db.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[baseline.companyId])).rows[0].run_id,baseline.runId);
    const sizes=(await db.query(`SELECT relname,pg_table_size(oid)::float8 AS table_bytes,pg_indexes_size(oid)::float8 AS index_bytes,
      pg_total_relation_size(oid)::float8 AS total_bytes FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) ORDER BY relname`,[tables])).rows;
    console.log(JSON.stringify({phase:'restored-summary-parity-passed',companyId:baseline.companyId,sourceRows:built.sourceRows,cveRows:all.length,
      buildMs:built.elapsedMs,readMs:timings,replayMs,allCveRowsMatched:true,summary:baseline.summary,storage:sizes,
      totalSummaryBytes:sizes.reduce((sum,row)=>sum+row.total_bytes,0),peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024)}));
  }
} finally {
  if(installed)await db.query('DROP TABLE spotlight_summary_current,spotlight_summary_cves,spotlight_summary_generations');
  await db.end();
}
