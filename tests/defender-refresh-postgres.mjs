import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,realpath} from 'node:fs/promises';
import pg from 'pg';
import {readDefenderRefreshSource} from '../lib/db/defender-refresh-source.mjs';
import {writeDefenderRefreshCandidate} from '../lib/db/defender-refresh-candidate.mjs';
import {reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
import {buildDefenderShadowReads} from '../lib/db/defender-shadow-reads.mjs';
import {publishDefenderShadow,readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
import {refreshModules,company,when,snapshot,storeFixture,inputFrom} from './defender-refresh-fixture.mjs';
import {verifyRefreshBaseline} from './defender-refresh-baseline-validation.mjs';
import {verifyDefenderWorkflow} from './defender-workflow-validation.mjs';
import {verifyLegacyHandoff} from './defender-handoff-validation.mjs';
import {verifyWriterOwnership} from './defender-ownership-validation.mjs';
import {verifyReverseExport} from './defender-reverse-export-validation.mjs';
import {verifyReverseReceipts} from './defender-reverse-receipt-validation.mjs';
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const suffix=randomUUID().replaceAll('-',''),sourceName=`vuln2_shadow_source_test_${suffix}`,targetName=`vuln2_shadow_test_${suffix}`;
const admin=new pg.Client({...options,database:'postgres'}),created=[];let source,target,writer,editor,pool,exportPool,checks=0;
const pass=message=>{checks++;console.log('PASS '+message);};
const modules=await refreshModules();
const {store,candidate:{prepareDefenderRefreshCandidate:prepare},source:{createDefenderStore}}=modules;
const run=randomUUID(),nextRun=randomUUID();
try{
  await admin.connect();for(const name of [sourceName,targetName]){await admin.query(`CREATE DATABASE ${name}`);created.push(name);}
  source=new pg.Client({...options,database:sourceName});target=new pg.Client({...options,database:targetName});writer=new pg.Client({...options,database:sourceName});
  editor=new pg.Client({...options,database:targetName});
  await Promise.all([source.connect(),target.connect(),writer.connect(),editor.connect()]);
  pool=new pg.Pool({...options,database:sourceName,max:1});const legacy=createDefenderStore(pool);await legacy.schema();
  for(const file of ['defender-platform-shadow','defender-shadow-reads','defender-shadow-publication','defender-shadow-refresh'])await target.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
  await source.query(`INSERT INTO defender_connections(company_id,tenant_id,client_id,secret,updated_by,current_run,last_success_at) VALUES($1,'fixture-tenant','fixture-client','unused','fixture',$2,$3)`,[company.id,run,when]);
  for(const id of [run,nextRun])await source.query(`INSERT INTO defender_import_runs(id,company_id,revision,status,phase,actor,finished_at,summary) VALUES($1,$2,1,'succeeded','Complete','fixture',$3,'{"findings":2,"inventoryDevices":1}')`,[id,company.id,when]);
  for(const id of [run,nextRun]){
    const d=snapshot().devices[0];await source.query('INSERT INTO defender_devices(run_id,device_id,record) VALUES($1,$2,$3)',[id,d.deviceId,JSON.stringify(d)]);
    for(let i=0;i<2;i++){const record={...snapshot().findings[0],softwareName:'Product',softwareVersion:`${i}`,remediation:'Install update',remediationId:'KB-fixture',exploitability:'ExploitIsPublic'};
      await source.query('INSERT INTO defender_records VALUES($1,$2,$3,$4,$5,$6,$7)',[id,`row-${i}`,record.deviceId,record.cve,record.severity,record.cvss,JSON.stringify(record)]);}
  }
  const fresh=await readDefenderRefreshSource(source,company.id),old=await legacy.platformSnapshot(company.id);assert.deepEqual(fresh.snapshot,old);assert.equal(fresh.snapshot.findings.length,1);
  pass('completed raw source aggregates software instances into the exact legacy device/CVE snapshot');
  const baseline=storeFixture();globalThis.__vulnStore=baseline;store.publishDefenderSnapshot(snapshot({runId:'old-run',observedAt:'2026-10-08T12:00:00Z'}));
  const saved=[...baseline.findings.values()][0];saved.status='Risk Accepted';saved.assignee='analyst';
  const input={...inputFrom(baseline),source:fresh},candidate=prepare(input,(f,inventory)=>store.riskFields(baseline,{...f,inventory}));
  const first=await writeDefenderRefreshCandidate(target,candidate);
  const persisted=value=>JSON.parse(JSON.stringify(value));
  const copied=(await target.query(reconstructShadowSql+' ORDER BY f.legacy_order',[company.id,first.projectionId])).rows.map(r=>r.record);assert.deepEqual(copied,persisted(candidate.records));
  store.publishDefenderSnapshot(fresh.snapshot);assert.deepEqual(copied,persisted([...baseline.findings.values()].filter(f=>f.defender)));
  const evidence=(await target.query('SELECT evidence FROM defender_shadow_refresh_candidates WHERE projection_id=$1',[first.projectionId])).rows[0].evidence;assert.deepEqual(evidence.assets,candidate.assets);assert.equal(evidence.baselineRun,'old-run');
  await buildDefenderShadowReads(target,company.id,first.projectionId);
  await publishDefenderShadow(target,{companyId:company.id,projectionId:first.projectionId,expectedRevision:0,actor:'fixture',reason:'test baseline'});
  const pointer=await readDefenderPublication(target,company.id);
  const retry=await writeDefenderRefreshCandidate(target,candidate);assert.notEqual(retry.projectionId,first.projectionId);assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  const digests=(await target.query('SELECT evidence->>\'recordDigest\' digest FROM defender_shadow_refresh_candidates ORDER BY projection_id')).rows;assert.equal(digests[0].digest,digests[1].digest);
  await assert.rejects(()=>target.query('UPDATE defender_shadow_refresh_candidates SET source_revision=2 WHERE projection_id=$1',[first.projectionId]),/append-only/);
  pass('candidate SQL matches actual legacy publication, preserves IDs/assignee/decisions/assets and cannot move the active pointer');
  const large={...candidate,records:Array.from({length:501},(_,i)=>({...candidate.records[0],id:`BATCH-${i}`,defender:{...candidate.records[0].defender,deviceId:`batch-${i}`}}))};
  let failedId;await assert.rejects(()=>writeDefenderRefreshCandidate(target,large,{afterBatch:({projectionId})=>{failedId=projectionId;throw Error('simulated interruption');}}),/interruption/);
  assert.equal((await target.query('SELECT state FROM defender_shadow_generations WHERE projection_id=$1',[failedId])).rows[0].state,'failed');
  assert.equal((await target.query('SELECT count(*)::int n FROM defender_shadow_findings WHERE projection_id=$1',[failedId])).rows[0].n,500);
  await assert.rejects(()=>buildDefenderShadowReads(target,company.id,failedId));
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  await assert.rejects(()=>writeDefenderRefreshCandidate(source,candidate),/Disposable target/);
  pass('interrupted candidates remain unreadable, previous publication is retained and source databases reject candidate writes');
  await target.query(await readFile('docs/sql/defender-shadow-refresh-publication-block.sql','utf8'));
  baseline.meta.defenderGenerations[company.id]='old-run';
  await verifyRefreshBaseline({source,target,writer,baseline,when,company,run,modules,pass});
  await verifyLegacyHandoff({source,target,pool,baseline,company,run,pass});
  await verifyDefenderWorkflow({source,target,editor,company,first,modules,pass});
  await verifyWriterOwnership({source,target,peer:editor,company,modules,first,pass,newClient:async()=>{
    const c=new pg.Client({...options,database:targetName});await c.connect();return c;
  }});
  exportPool=new pg.Pool({...options,database:targetName,max:1});
  await verifyReverseExport({source,target,pool,exportPool,company,run,modules,pass});
  await verifyReverseReceipts({source,target,peer:editor,pool,company,run,modules,pass,newClient:async()=>{
    const c=new pg.Client({...options,database:targetName});await c.connect();return c;
  }});
  const pinned=await readDefenderRefreshSource(source,company.id,{afterSelected:async selected=>{
    assert.equal(selected,run);await writer.query('UPDATE defender_connections SET current_run=$1 WHERE company_id=$2',[nextRun,company.id]);
    await writer.query('DELETE FROM defender_records WHERE run_id=$1',[run]);await writer.query('DELETE FROM defender_devices WHERE run_id=$1',[run]);
  }});assert.deepEqual(pinned,fresh);assert.equal((await readDefenderRefreshSource(source,company.id)).snapshot.runId,nextRun);
  pass('one read-only snapshot survives concurrent source-pointer replacement and pruning without mixing runs');
  await source.query('UPDATE defender_connections SET revision=2');await assert.rejects(()=>readDefenderRefreshSource(source,company.id),/Complete matching/);await source.query('UPDATE defender_connections SET revision=1');
  await source.query("UPDATE defender_import_runs SET status='failed' WHERE id=$1",[nextRun]);await assert.rejects(()=>readDefenderRefreshSource(source,company.id),/Complete matching/);await source.query("UPDATE defender_import_runs SET status='succeeded' WHERE id=$1",[nextRun]);
  await source.query('DELETE FROM defender_records WHERE run_id=$1',[nextRun]);await assert.rejects(()=>readDefenderRefreshSource(source,company.id),/counts differ/);
  await source.query("UPDATE defender_import_runs SET summary=$2::jsonb WHERE id=$1",[nextRun,JSON.stringify({findings:0,inventoryDevices:1})]);
  assert.equal((await readDefenderRefreshSource(source,company.id)).snapshot.findings.length,0);
  const empty=await writeDefenderRefreshCandidate(target,{...candidate,records:[],assets:[]});
  await buildDefenderShadowReads(target,company.id,empty.projectionId);
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  pass('revision drift, failed imports and incomplete retained rows fail closed; verified empty imports remain valid');
  console.log(JSON.stringify({checks,passed:true,productionWrites:0,sourceApiCalls:0,ticketsSent:0}));
}finally{
  await exportPool?.end();await pool?.end();for(const c of [source,target,writer,editor])await c?.end().catch(()=>{});
  for(const name of created.reverse())await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();
}
