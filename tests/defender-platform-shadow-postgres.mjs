import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,realpath} from 'node:fs/promises';
import pg from 'pg';
import {buildDefenderPlatformShadow as build,readDefenderShadowTotals as totals,reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const suffix=randomUUID().replaceAll('-',''),sourceName=`vuln2_shadow_source_test_${suffix}`,targetName=`vuln2_shadow_test_${suffix}`;
const admin=new pg.Client({...options,database:'postgres'}),created=[];let source,target,restored,checks=0;
const ok=message=>{checks++;console.log(`PASS ${message}`);};
const run=randomUUID(),first={id:'F-1',companyId:'CO-A',cve:'CVE-2026-1234',asset:'asset-1',connector:'defender',
  status:'Risk Accepted',assignee:'operator',firstSeen:'2026-01-01',lastSeen:'2026-09-01',resolvedAt:null,
  severity:'High',cvss:8.1,realRisk:42,riskPriority:'Medium',remediation:'Recommended fix',kev:true,
  seenBy:['defender','nessus'],futureField:{preserved:[null,'value']},
  defender:{deviceId:'device-1',runId:'older-generation',observedAt:'2026-09-01',active:true,cvss:null,remediation:'Source fix',otherRemediation:'Prior scanner fix'}};
try{
  await admin.connect();const {rows:[guard]}=await admin.query("SELECT current_setting('data_directory') AS dir,current_setting('listen_addresses') AS listen");
  assert.equal(await realpath(guard.dir),await realpath(`${socket}/../data`));assert.equal(guard.listen,'');
  for(const name of [sourceName,targetName]){await admin.query(`CREATE DATABASE ${name}`);created.push(name);}
  source=new pg.Client({...options,database:sourceName});target=new pg.Client({...options,database:targetName});
  source.on('error',()=>{});target.on('error',()=>{});
  await source.connect();await target.connect();await target.query(await readFile('docs/sql/defender-platform-shadow.sql','utf8'));
  await source.query(`CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb,updated_at timestamptz DEFAULT now());
    CREATE TABLE defender_connections(company_id text,revision int,current_run uuid);
    CREATE TABLE defender_import_runs(id uuid,company_id text,revision int,status text);`);
  await source.query("INSERT INTO defender_connections VALUES('CO-A',1,$1);",[run]);
  await source.query("INSERT INTO defender_import_runs VALUES($1,'CO-A',1,'succeeded')",[run]);
  await source.query("INSERT INTO vuln_store(key,data) VALUES('meta',$1),('companies:00',$2)",[
    {meta:{defenderGenerations:{'CO-A':run}}},JSON.stringify([['CO-A',{id:'CO-A',name:'Fixture',isDemo:false}]])]);
  for(let i=0;i<64;i++)await source.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',[`findings:${String(i).padStart(2,'0')}`,'[]']);
  const second={...first,id:'F-2',cve:'CVE-2026-2345',connector:'nessus',status:'Resolved',resolvedAt:'2026-10-01',defender:{...first.defender,active:false}};
  const foreign={...first,id:'foreign',companyId:'CO-B'};
  const setRows=async rows=>source.query("UPDATE vuln_store SET data=$1 WHERE key='findings:00'",[JSON.stringify(rows.map(f=>[f.id,f]))]);
  await setRows([first,second,foreign]);
  const initial=await build(source,target,'CO-A');assert.equal(initial.count,2);
  const {rows:roundtrip}=await target.query(reconstructShadowSql+' ORDER BY f.finding_id',['CO-A',initial.projectionId]);
  assert.deepEqual(roundtrip.map(r=>r.record),[first,second]);
  assert.equal((await totals(target,'CO-A',initial.projectionId)).length,2);
  await assert.rejects(()=>totals(target,'CO-B',initial.projectionId),/Verified customer projection/);
  ok('all fields round-trip, including accepted/resolved states, risk, old/null evidence, extensions and customer isolation');

  await assert.rejects(()=>target.query(`INSERT INTO defender_shadow_workflow VALUES('CO-B',$1,'F-1','Open',NULL,'a','b',NULL)`,[initial.projectionId]),e=>e.code==='23503');
  ok('composite foreign keys reject cross-customer evidence/workflow relationships');
  const more=Array.from({length:501},(_,i)=>({...first,id:`M-${i}`,cve:`CVE-2026-${10000+i}`}));
  await setRows(more);
  await assert.rejects(()=>build(source,target,'CO-A',{afterBatch:({batches})=>{if(batches===1)throw new Error('Injected failure');}}),/Injected failure/);
  const {rows:[failed]}=await target.query("SELECT projection_id FROM defender_shadow_generations WHERE state='failed'");
  assert.ok(failed);assert.equal((await target.query('SELECT count(*)::int n FROM defender_shadow_findings WHERE projection_id=$1',[failed.projection_id])).rows[0].n,500);
  await assert.rejects(()=>totals(target,'CO-A',failed.projection_id),/Verified customer projection/);
  assert.equal((await totals(target,'CO-A',initial.projectionId)).length,2);
  ok('interrupted batches remain failed and unreadable; previous verified projection stays available');

  await setRows([first,{...first,id:'duplicate-pair'}]);
  await assert.rejects(()=>build(source,target,'CO-A'),e=>e.code==='23505');
  await source.query("UPDATE defender_connections SET revision=2");
  await assert.rejects(()=>build(source,target,'CO-A'),/generations must match/);
  await source.query("UPDATE defender_connections SET revision=1");
  await setRows([first]);const retry=await build(source,target,'CO-A');assert.equal(retry.count,1);
  assert.notEqual(retry.projectionId,initial.projectionId);
  ok('duplicate source identities and revision drift fail; retry creates an independent verified generation');
  await source.query(`UPDATE vuln_store SET data=$1 WHERE key='companies:00'`,[JSON.stringify([['CO-A',{id:'CO-A',name:'Fixture',isDemo:'true'}]])]);
  await assert.rejects(()=>build(source,target,'CO-A'),/Known non-demo customer/);
  await source.query(`UPDATE vuln_store SET data=$1 WHERE key='companies:00'`,[JSON.stringify([['CO-A',{id:'CO-A',name:'Fixture',isDemo:false}]])]);
  await assert.rejects(()=>target.query(`INSERT INTO defender_shadow_generations(company_id,projection_id,model_version,source_run,snapshot_saved_at,state,verified_at)
    VALUES('CO-A',$1,1,'test',now(),'verified',now())`,[randomUUID()]),e=>e.code==='23514');
  ok('malformed demo metadata and verified generations without a row count fail closed');
  if(process.argv.includes('--with-restored-defender')){
    restored=new pg.Client({...options,database:'recovery_application'});restored.on('error',()=>{});await restored.connect();
    const result=await build(restored,target,'CO-230784',{afterBatch:({count,batches,elapsedMs})=>{if(batches<=3||batches%20===0)console.log(JSON.stringify({phase:'shadow-roundtrip',count,elapsedMs}));}});
    assert.equal(result.count,288878);
    const byStatus=await target.query(`SELECT status,count(*)::int n FROM defender_shadow_workflow WHERE company_id=$1 AND projection_id=$2 GROUP BY status ORDER BY status`,[result.companyId,result.projectionId]);
    assert.deepEqual(byStatus.rows,[{status:'Open',n:215891},{status:'Resolved',n:72987}]);
    const timing=performance.now(),summary=await totals(target,result.companyId,result.projectionId),readMs=performance.now()-timing;
    const {rows:[retained]}=await target.query(`SELECT count(*)::int n FROM defender_shadow_evidence e JOIN defender_shadow_workflow w USING(company_id,projection_id,finding_id)
      WHERE company_id=$1 AND projection_id=$2 AND w.status='Open' AND e.source_run<>$3 AND e.active`,[result.companyId,result.projectionId,result.sourceRun]);
    assert.equal(retained.n,2970);
    const {rows:[size]}=await target.query("SELECT sum(pg_total_relation_size(oid))::text bytes FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'");
    console.log(JSON.stringify({phase:'restored-shadow-verified',...result,summary,summaryReadMs:Math.round(readMs),tableIndexBytes:Number(size.bytes),peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024)}));
    ok('all 288878 restored findings round-trip; 2970 older open findings and 72987 resolved records retained');
  }
  console.log(`Passed ${checks} PostgreSQL scenarios; no production connection or publication.`);
} catch(error) {
  // PostgreSQL constraint details and assertion diffs can include private finding payloads.
  console.error(JSON.stringify({phase:'shadow-validation-failed',code:error.code??'VALIDATION_FAILED'}));
  process.exitCode=1;
} finally {
  await restored?.end();await source?.end();await target?.end();
  for(const name of created.reverse())await admin.query(`DROP DATABASE ${name}`);
  await admin.end();
}
