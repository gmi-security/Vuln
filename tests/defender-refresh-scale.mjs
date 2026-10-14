import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,realpath,writeFile} from 'node:fs/promises';
import pg from 'pg';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {refreshModules} from './defender-refresh-fixture.mjs';
import {readDefenderShadow} from '../lib/db/defender-shadow-reads.mjs';
import {publishDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const admin=new pg.Client({...options,database:'postgres'}),source=new pg.Client({...options,database:'recovery_application'}),name=`vuln2_shadow_test_${randomUUID().replaceAll('-','')}`;
let target,created=false;const companyId='CO-230784',report={scope:'retained Defender cohort, same applied import; not live data'};
try{
  await admin.connect();await source.connect();await source.query('SET default_transaction_read_only=on');
  await admin.query(`CREATE DATABASE ${name}`);created=true;target=new pg.Client({...options,database:name});await target.connect();
  for(const file of ['defender-platform-shadow','defender-shadow-reads','defender-shadow-publication','defender-shadow-refresh','defender-shadow-refresh-publication-block'])await target.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
  const {candidate:{prepareDefenderRefreshCandidate:prepare},assessment:{captureDefenderRefreshAssessment:capture}}=await refreshModules();
  let expectedRecords,expectedOpen,expectedCves;
  const result=await buildDefenderRefresh(source,target,companyId,{prepare,capture,afterCollect(input){
    assert.equal(input.baseline.runId,input.source.snapshot.runId,'This test requires the already-applied retained import');
    const records=input.baseline.findings.filter(f=>f.defender);expectedRecords=records.length;
    const open=records.filter(f=>['Open','In Remediation'].includes(f.status));expectedOpen=open.length;expectedCves=new Set(open.map(f=>f.cve.toUpperCase())).size;
    console.log(JSON.stringify({phase:'collected',records:expectedRecords,sourcePairs:input.source.snapshot.findings.length,devices:input.source.snapshot.devices.length}));
  },afterPlan(candidate,input){assert.equal(candidate.sameRun,true);assert.equal(candidate.changedFindings,0);assert.deepEqual(candidate.records,input.baseline.findings.filter(f=>f.defender));},
  afterBatch({batches,count}){if(batches%100===0)console.log(JSON.stringify({phase:'writing',batches,count}));}});
  assert.equal(result.state,'comparison-only');assert.equal(result.count,expectedRecords);assert.equal(result.publicationAllowed,false);
  const summary=await readDefenderShadow(target,{companyId,projectionId:result.projectionId});assert.equal(summary.summary.records,expectedRecords);assert.equal(summary.summary.openRemediation,expectedOpen);assert.equal(summary.summary.uniqueOpenCves,expectedCves);
  await assert.rejects(()=>publishDefenderShadow(target,{companyId,projectionId:result.projectionId,expectedRevision:0,actor:'scale-test',reason:'must remain blocked'}),/comparison-only/);
  Object.assign(report,{passed:true,records:expectedRecords,open:expectedOpen,cves:expectedCves,timings:result.timings,peakRssKiB:process.resourceUsage().maxRSS,
    bytes:Number((await target.query('SELECT pg_database_size(current_database())::text bytes')).rows[0].bytes),productionWrites:0});
  await writeFile('refresh-scale-result.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}finally{
  await source.end().catch(()=>{});await target?.end().catch(()=>{});if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();
}
