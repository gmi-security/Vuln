// Explicit private restore only. No application initialization, env loading or writes to SQL.
import assert from 'node:assert/strict';
import {realpath, writeFile, readFile} from 'node:fs/promises';
import pg from 'pg';
import {createComparison, createPlatformTotals} from './source-platform-comparison.mjs';
const socket=await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'),'Private socket required');
const output=process.argv[3];
assert.ok(output?.startsWith('/home/codex/vuln-recovery/') && output.endsWith('.json'),'Private report required');
const client=new pg.Client({host:socket,port:55483,user:'codex',database:'recovery_application',
  connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000});
const started=Date.now(), deadline=started+300000;
const query=async(sql,params=[])=>{assert.ok(Date.now()<deadline,'Audit deadline exceeded');return (await client.query(sql,params)).rows;};
const companies=['CO-230784','CO-147284'];
try {
  await client.connect();
  const [isolation]=await query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen");
  assert.equal(await realpath(isolation.data),await realpath(`${socket}/../data`));assert.equal(isolation.listen,'');
  await query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  await query("SET LOCAL idle_in_transaction_session_timeout='30s'");
  const [meta]=await query("SELECT data->'meta'->'defenderGenerations' AS generations, data ? 'findings' AS override, updated_at FROM vuln_store WHERE key='meta'");
  assert.ok(meta && !meta.override,'Unsupported snapshot layout');
  const buckets=await query("SELECT key,jsonb_typeof(data) AS type FROM vuln_store WHERE key LIKE 'findings:%' ORDER BY key");
  assert.deepEqual(buckets.map(r=>r.key),Array.from({length:64},(_,i)=>`findings:${String(i).padStart(2,'0')}`));
  assert.ok(buckets.every(r=>r.type==='array'));
  const [connection]=await query(`SELECT c.company_id,c.current_run,c.revision,r.revision AS run_revision,r.status,r.finished_at
    FROM defender_connections c JOIN defender_import_runs r ON r.id=c.current_run AND r.company_id=c.company_id WHERE c.company_id=$1`,[companies[0]]);
  assert.ok(connection?.status==='succeeded','Completed owned Defender generation required');
  const devices=await query("SELECT device_id AS device,record->>'lastSeen' AS heartbeat FROM defender_devices WHERE run_id=$1 LIMIT 100001",[connection.current_run]);
  assert.ok(devices.length<=100000);
  const rows=await query(`SELECT device_id AS device,cve,count(*)::int AS instances,
    (ARRAY['UNKNOWN','NONE','LOW','MEDIUM','HIGH','CRITICAL'])[MAX(CASE severity WHEN 'CRITICAL' THEN 6 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 4 WHEN 'LOW' THEN 3 WHEN 'NONE' THEN 2 ELSE 1 END)] AS severity,
    MAX(cvss) AS cvss FROM defender_records WHERE run_id=$1 GROUP BY device_id,cve LIMIT 500001`,[connection.current_run]);
  assert.ok(rows.length<=500000,'Pair limit exceeded');
  const comparison=createComparison(rows,new Map(devices.map(r=>[r.device,r.heartbeat])),connection.current_run,meta.generations?.[companies[0]]);
  const totals=new Map(companies.map(id=>[id,createPlatformTotals()]));
  let scanned=0;
  for(const {key} of buckets){
    const [valid]=await query(`SELECT count(*)::int AS n,count(*) FILTER (WHERE jsonb_typeof(e)!='array' OR jsonb_array_length(e)!=2 OR jsonb_typeof(e->1)!='object' OR e->>0 IS DISTINCT FROM e->1->>'id')::int AS malformed
      FROM vuln_store CROSS JOIN LATERAL jsonb_array_elements(data) e WHERE key=$1`,[key]);
    assert.equal(valid.malformed,0,'Unsupported finding entry');scanned+=valid.n;assert.ok(scanned<=1000000,'Snapshot limit exceeded');
    const findings=await query(`SELECT f->>'companyId' AS company,f->>'cve' AS cve,f->>'asset' AS asset,
      f->>'connector' AS connector,f->>'status' AS status,f->>'severity' AS severity,f->>'cvss' AS cvss,
      f->'seenBy' AS "seenBy",f->'defender'->>'deviceId' AS device,f->'defender'->>'runId' AS run,
      f->'defender'->'active' AS active,f->'defender'->>'observedAt' AS observed
      FROM vuln_store CROSS JOIN LATERAL jsonb_array_elements(data) e CROSS JOIN LATERAL (SELECT e->1 AS f) x
      WHERE key=$1 AND f->>'companyId'=ANY($2::text[])`,[key,companies]);
    for(const f of findings){totals.get(f.company).add(f);if(f.company===companies[0])comparison.add(f);}
  }
  // Existing independently audited source baseline is usable only with the same retained pointer.
  const baseline=JSON.parse(await readFile('/home/codex/vuln-recovery/spotlight-summary-v0w2r55z/spotlight-summary-baseline.json','utf8'));
  const atlas=baseline.find(r=>r.companyId===companies[1]);assert.ok(atlas);
  const pointers=await query(`SELECT c.run_id,r.status,r.finished_at FROM spotlight_import_current c
    JOIN spotlight_import_runs r ON r.id=c.run_id AND r.tenant_key=c.tenant_key WHERE c.tenant_key=$1`,[companies[1]]);
  assert.equal(pointers.length,1);assert.equal(pointers[0].run_id,atlas.runId,'Independent baseline generation changed');
  assert.equal(pointers[0].status,'completed');
  await query('ROLLBACK');
  const report={format:1,auditedAt:new Date().toISOString(),backupDate:'2026-10-09',elapsedMs:Date.now()-started,
    snapshotMetaUpdatedAt:meta.updated_at,scannedPlatformRecords:scanned,
    defender:{companyId:companies[0],sourceRun:connection.current_run,publishedRun:meta.generations?.[companies[0]],
      revisionMatches:connection.revision===connection.run_revision,completedAt:connection.finished_at,inventoryDevices:devices.length,...comparison.finish()},
    platform:Object.fromEntries([...totals].map(([id,t])=>[id,t.finish()])),
    spotlight:{companyId:companies[1],runId:atlas.runId,completedAt:pointers[0].finished_at,sourceRows:atlas.sourceRows,summary:atlas.summary,
      comparison:'Not proven: platform finding identity/generation lineage to this retained Spotlight import is unavailable. Source counts cannot replace platform totals.'}};
  await writeFile(output,JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
  console.log(JSON.stringify(report,null,2));
} finally {await client.end();}
