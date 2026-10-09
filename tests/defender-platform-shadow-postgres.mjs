import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,realpath} from 'node:fs/promises';
import pg from 'pg';
import {buildDefenderPlatformShadow as build,readDefenderShadowTotals as totals,reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000,query_timeout:20000};
const suffix=randomUUID().replaceAll('-',''),sourceName=`vuln2_shadow_source_test_${suffix}`,targetName=`vuln2_shadow_test_${suffix}`;
const admin=new pg.Client({...options,database:'postgres'}),created=[];let source,target,restored,observer,writer,checks=0;
const ok=message=>{checks++;console.log(`PASS ${message}`);};
const readValidation=process.argv.includes('--with-shadow-reads')?await import('./defender-shadow-read-validation.mjs'):null;
const cveValidation=process.argv.includes('--with-shadow-cve')?await import('./defender-shadow-cve-validation.mjs'):null;
const adapterValidation=process.argv.includes('--with-customer-cve')?await import('./shadow-customer-cve-validation.mjs'):null;
const publicationValidation=process.argv.includes('--with-publication')?await import('./defender-shadow-publication-validation.mjs'):null;
assert.ok(!publicationValidation||![readValidation,cveValidation,adapterValidation,process.argv.includes('--with-restored-defender')].some(Boolean),
  'Run publication fixtures separately: earlier mutation-based readers do not model immutable generations');
const run=randomUUID(),first={id:'F-1',companyId:'CO-A',cve:'CVE-2026-1234',asset:'asset-1',connector:'defender',
  title:'Fixture vulnerability',
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
  if(cveValidation||adapterValidation)await target.query(await readFile('docs/sql/defender-shadow-cve.sql','utf8'));
  if(readValidation||publicationValidation){
    await target.query(await readFile('docs/sql/defender-shadow-reads.sql','utf8'));
    observer=new pg.Client({...options,database:targetName});observer.on('error',()=>{});await observer.connect();
    if(publicationValidation){writer=new pg.Client({...options,database:targetName});writer.on('error',()=>{});await writer.connect();}
  }
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
    VALUES('CO-A',$1,2,'test',now(),'verified',now())`,[randomUUID()]),e=>e.code==='23514');
  ok('malformed demo metadata and verified generations without a row count fail closed');
  if(readValidation){
    await readValidation.verifyShadowReads(target,initial,[first,second],{failure:true,observer});
    const fixtures=Array.from({length:703},(_,i)=>({...first,id:`SORT-${String(1000-i)}`,cve:i===700?'NO-CVE':`CVE-2026-${1000+Math.floor(i/3)}`,
      asset:`asset-${i%7}`,connector:i%23===0?'spiderfoot':i%29===0?'burp':'defender',
      severity:['Critical','High','Medium','Low','Info'][i%5],cvss:i%3?8:9,realRisk:i%4?50:70,
      status:['Open','In Remediation','Risk Accepted','False Positive','Resolved'][i%5],
      defender:{...first.defender,deviceId:`device-${i}`,runId:run}}));
    await setRows(fixtures);const fixtureProjection=await build(source,target,'CO-A');
    console.log(JSON.stringify({phase:'fixture-read-parity',...await readValidation.verifyShadowReads(target,fixtureProjection,fixtures,{failure:true,observer})}));
    await setRows([]);const empty=await build(source,target,'CO-A');await readValidation.verifyShadowReads(target,empty,[]);
    ok('saved summaries and complete keyset traversal match legacy filters, stable risk ties, CVE grouping, empty and rollback states');
  }
  if(cveValidation){
    const fixtures=Array.from({length:1103},(_,i)=>({...first,id:`C-${1103-i}`,cve:i===1100?'CVE-2026-9876':i===1101?'CVE-2026-9877':i===1102?'CVE-2026-9878':i%2?'cve-2026-1234':'CVE-2026-1234',
      asset:`=device-${i%79}`,connector:i%37===0?'spiderfoot':i%41===0?'burp':i%43===0?'nessus':'defender',
      remediation:i===1100?'':i%2?'Install "approved" update\nThen reboot':'Apply recommended patch',
      status:i%13===0?'Resolved':i%5===0?'In Remediation':'Open',realRisk:i%4?42:70,
      defender:{...first.defender,deviceId:`device-${i}`,hostname:`@host-${i}`,runId:i%3?run:'older-generation'}}));
    await setRows([...fixtures,foreign]);const projection=await build(source,target,'CO-A');
    console.log(JSON.stringify({phase:'fixture-cve-parity',...await cveValidation.verifyCveReads(target,projection,fixtures,['CVE-2026-1234','CVE-2026-9876','CVE-2026-9877','CVE-2026-9878'])}));
    const {readDefenderShadowCve}=await import('../lib/db/defender-shadow-cve.mjs');
    await target.query("UPDATE defender_shadow_findings SET detail=jsonb_set(detail,'{oversized}',to_jsonb(repeat('x',33554432))) WHERE company_id=$1 AND projection_id=$2 AND issue_key='CVE-2026-9877'",['CO-A',projection.projectionId]);
    await assert.rejects(()=>readDefenderShadowCve(target,{companyId:'CO-A',projectionId:projection.projectionId,cve:'CVE-2026-9877'}),e=>e.status===413);
    ok('CVE detail and complete patch packet parity, mixed-case keys, correlated evidence, exclusions, CSV escaping, missing remediation and payload cap');
  }
  if(adapterValidation){
    const fixtures=Array.from({length:6},(_,i)=>({...first,id:`ADAPTER-${i}`,asset:`asset-${i}`,status:'Open',
      cve:i%2?'cve-2026-1234':'CVE-2026-1234',realRisk:42+i,
      defender:{...first.defender,deviceId:`device-${i}`,runId:run}}));
    await setRows([...fixtures,foreign]);const projection=await build(source,target,'CO-A');
    console.log(JSON.stringify({phase:'customer-cve-adapter',...await adapterValidation.verifyCustomerCveAdapter(source,target,projection,[...fixtures,foreign])}));
    ok('disabled adapter composes scoped shadow findings, separate enrichment storage and existing ticket references/exclusions');
  }
  if(publicationValidation){
    console.log(JSON.stringify({phase:'shadow-publication',...await publicationValidation.verifyPublication(source,target,observer,writer,first)}));
    ok('immutable generations, complete saved reads, atomic publication, rollback, concurrent readers/writers and append-only history');
  }
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
    if(cveValidation){
      const reference=await cveValidation.restoredCveReference(restored,result.companyId);
      console.log(JSON.stringify({phase:'restored-cve-parity',...await cveValidation.verifyCveReads(target,result,reference.records,reference.cves),referenceRecords:reference.records.length}));
      ok('sampled restored CVE details and pure patch packets match independent source records including exact exclusion keys');
    }
    if(readValidation){
      console.log(JSON.stringify({phase:'restored-reference-start'}));
      const reference=await readValidation.savedReference(restored,result.companyId);
      console.log(JSON.stringify({phase:'restored-derived-read-start'}));
      console.log(JSON.stringify({phase:'restored-read-parity',...await readValidation.verifyShadowReads(target,result,reference)}));
      const {rows:[derivedSize]}=await target.query("SELECT sum(pg_total_relation_size(oid))::text bytes FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' AND relname IN('defender_shadow_read_summary','defender_shadow_priority','defender_shadow_cve_pages')");
      console.log(JSON.stringify({phase:'derived-read-storage',bytes:Number(derivedSize.bytes),peakRssMiB:Math.round(process.resourceUsage().maxRSS/1024)}));
      ok('every restored priority/CVE page and saved totals match the independent source/reporting reference');
    }
  }
  console.log(`Passed ${checks} PostgreSQL scenarios; no production connection or publication.`);
} catch(error) {
  // PostgreSQL constraint details and assertion diffs can include private finding payloads.
  console.error(JSON.stringify({phase:'shadow-validation-failed',step:error.auditPhase,code:error.code??'VALIDATION_FAILED',
    location:error.stack?.split('\n').filter(line=>/^\s+at /.test(line)).slice(0,8)}));
  process.exitCode=1;
} finally {
  await restored?.end();await source?.end();await writer?.end();await observer?.end();await target?.end();
  for(const name of created.reverse()){
    if(process.exitCode&&process.argv.includes('--keep-failed-shadow')&&name===targetName){console.log(`PRIVATE_FAILED_TARGET=${name}`);continue;}
    await admin.query(`DROP DATABASE ${name}`);
  }
  await admin.end();
}
