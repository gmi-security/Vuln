import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {loadSpotlightSummaryModules} from '../scripts/source-read-model-loader.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const options={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const admin=new pg.Client({...options,database:'postgres'}),name=`vuln2_summary_test_${randomUUID().replaceAll('-','')}`;
const {createSpotlightSummaryStore:create,SPOTLIGHT_SUMMARY_VERSION:VERSION}=await loadSpotlightSummaryModules();
const request={companyId:'CO-A',now:new Date('2026-10-10'),staleAfterMs:86400000};
let db,created=false,checks=0;const disconnected=[],ok=message=>{checks++;console.log(`PASS ${message}`);};
const migration=await readFile('docs/sql/spotlight-source-summaries.sql','utf8');
const sample=(id,cve='CVE-2026-1000',aid='host')=>({id,cid:'a'.repeat(32),aid,status:'open',cve:{id:cve,severity:'HIGH',base_score:8},suppression_info:{is_suppressed:false}});
try {
  await admin.connect();
  const isolation=(await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/')&&!isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Pool({...options,database:name,max:6});
  db.on('connect',client=>disconnected.push(new Promise(resolve=>client.once('end',resolve))));
  const store=create(db);
  assert.equal((await store.read(request)).state,'not-installed');await assert.rejects(()=>store.build('CO-A','tester'),e=>e.code==='42P01');
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n,0);
  await db.query(`CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY,tenant_key text,status text,started_at timestamptz,finished_at timestamptz,checkpoint_version int,expected_count bigint,hydrated_count bigint);
    CREATE TABLE spotlight_import_current(tenant_key text PRIMARY KEY,run_id uuid);
    CREATE TABLE spotlight_import_records(run_id uuid,tenant_key text,company_id text,source_id text,cve text,status text,raw jsonb,PRIMARY KEY(run_id,tenant_key,source_id));`);
  await db.query(migration);
  ok('explicit migration required; no automatic schema or source mutation');
  async function install(company,entries,storedFields={}) {
    const run=randomUUID();await db.query("INSERT INTO spotlight_import_runs VALUES($1,$2,'completed',now(),now(),3,$3,$3)",[run,company,entries.length]);
    for(const raw of entries)await db.query('INSERT INTO spotlight_import_records VALUES($1,$2,$2,$3,$4,$5,$6)',
      [run,company,storedFields.source_id??raw.id,storedFields.cve??raw.cve?.id,storedFields.status??raw.status,raw]);
    await db.query('INSERT INTO spotlight_import_current VALUES($1,$2) ON CONFLICT(tenant_key) DO UPDATE SET run_id=EXCLUDED.run_id',[company,run]);return run;
  }
  const first=await install('CO-A',[sample('1'),sample('2'),sample('3','CVE-2026-2000','other')]);
  assert.equal((await store.read(request)).state,'summary-pending');
  const streaming=create({connect:async()=>{const client=await db.connect();return {release:(v)=>client.release(v),query:(sql,args)=>{
    assert.ok(!(sql.includes('spotlight_import_records') && /COUNT\s*\(/i.test(sql)), 'large imports must validate counts during the bounded scan, not an upfront full-source count');
    return client.query(sql,args);
  }};}});
  assert.equal((await streaming.build('CO-A','tester')).state,'built');
  assert.equal((await store.build('CO-A','tester')).state,'reused');
  const result=await store.read({...request,limit:1});assert.equal(result.state,'available');assert.equal(result.projection.state,'ready');
  const savedFixes=(await db.query("SELECT summary->'topFixes' AS fixes FROM spotlight_summary_generations WHERE run_id=$1",[first])).rows[0].fixes;
  assert.equal(savedFixes.companyId,'CO-A');assert.equal(savedFixes.missingRemediation,3);assert.equal(savedFixes.totalFixes,0);
  assert.equal('topFixes' in result.summary,false);
  assert.equal(result.summary.sourceInstances,3);assert.equal(result.summary.deviceCveFindings,2);assert.equal(result.cves.total,2);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations')).rows[0].n,1);
  const noRaw=create({connect:async()=>{const client=await db.connect();return{release:()=>client.release(),query:(sql,args)=>{assert.ok(!sql.includes('spotlight_import_records'),'page reader must not scan raw records');return client.query(sql,args);}};}});
  assert.equal((await noRaw.read(request)).summary.sourceInstances,3);
  assert.equal((await store.read({...request,companyId:'CO-B'})).state,'no-completed-import');
  ok('atomic publication, replay without duplication, bounded pages, customer isolation and no raw records on reads');
  const guarded=await noRaw.read({...request,spotlightTenant:'a'.repeat(32)});
  assert.equal(guarded.state,'available');assert.doesNotMatch(JSON.stringify(guarded),/vendorScope|aaaaaaaa/);
  assert.equal((await noRaw.read({...request,spotlightTenant:'b'.repeat(32)})).state,'inconsistent');
  ok('tenant guarded reader validates whole-generation CID without returning it or scanning source rows');
  // Older summaries remain readable while the new worklist is being built.
  for(const older of [3,4]) {
    await db.query("INSERT INTO spotlight_summary_generations SELECT company_id,run_id,$2,source_completed_at,source_rows,count_verification,summary,cve_count,built_at,built_by FROM spotlight_summary_generations WHERE run_id=$1 AND model_version=$3",[first,older,VERSION]);
    await db.query("INSERT INTO spotlight_summary_cves(company_id,run_id,model_version,cve,severity,cvss,affected_devices,source_instances) SELECT company_id,run_id,$2,cve,severity,cvss,affected_devices,source_instances FROM spotlight_summary_cves WHERE run_id=$1 AND model_version=$3",[first,older,VERSION]);
    await db.query("UPDATE spotlight_summary_current SET model_version=$1 WHERE company_id='CO-A'",[older]);
    const compatible=await noRaw.read(request);assert.equal(compatible.state,'available');assert.equal(compatible.summary.sourceInstances,3);assert.equal(compatible.cves.total,2);assert.equal(compatible.projection.state,'pending');
    await db.query("UPDATE spotlight_summary_current SET model_version=$1 WHERE company_id='CO-A'",[VERSION]);
    await db.query("DELETE FROM spotlight_summary_generations WHERE model_version=$1",[older]);
  }
  ok('v3 and v4 summaries remain readable with projection pending during the v5 upgrade');

  const hold=await db.connect();await hold.query('SELECT pg_advisory_lock(804244,1)');
  assert.equal((await store.build('CO-A','tester')).state,'busy');await hold.query('SELECT pg_advisory_unlock(804244,1)');hold.release();
  ok('global build lock prevents overlapping memory-heavy builders');
  const second=await install('CO-A',[sample('4','CVE-2026-3000')]);
  const pending=await store.read(request);assert.equal(pending.generation.id,first);assert.equal(pending.projection.state,'pending');assert.equal(pending.projection.currentImportId,second);
  assert.equal((await store.read({...request,spotlightTenant:'a'.repeat(32)})).state,'inconsistent');
  await db.query(`CREATE FUNCTION reject_summary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test publication failure'; END $$;
    CREATE TRIGGER reject_summary BEFORE INSERT ON spotlight_summary_current FOR EACH ROW EXECUTE FUNCTION reject_summary()`);
  await assert.rejects(()=>store.build('CO-A','tester'),/test publication failure/);
  assert.equal((await store.read(request)).generation.id,first);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations')).rows[0].n,1);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_cves')).rows[0].n,2);
  await db.query('DROP TRIGGER reject_summary ON spotlight_summary_current;DROP FUNCTION reject_summary()');
  ok('failed publication rolls back header/CVE rows and preserves the previous visible summary');
  let oldSeen=false;
  const observe=create({connect:async()=>{const client=await db.connect();return {release:(v)=>client.release(v),query:async(sql,args)=>{
    const response=await client.query(sql,args);
    if(sql.startsWith('INSERT INTO public.spotlight_summary_cves')) {const during=await store.read(request);assert.equal(during.generation.id,first);oldSeen=true;}
    return response;
  }};}});
  assert.equal((await observe.build('CO-A','tester')).state,'built');assert.ok(oldSeen);assert.equal((await store.read(request)).generation.id,second);
  ok('concurrent reads see a complete previous generation while the new rows are being inserted');
  const third=await install('CO-A',[sample('5','CVE-2026-4000')]);let newer;
  const supersede=create({connect:async()=>{const client=await db.connect();return {release:(v)=>client.release(v),query:async(sql,args)=>{
    const response=await client.query(sql,args);
    if(sql.includes('CROSS JOIN LATERAL jsonb_to_record(r.raw)')&&!newer)newer=await install('CO-A',[]);
    return response;
  }};}});
  assert.equal((await supersede.build('CO-A','tester')).state,'superseded');assert.equal((await store.read(request)).generation.id,second);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE run_id=$1',[third])).rows[0].n,0);
  assert.equal((await store.build('CO-A','tester')).state,'built');const empty=await store.read(request);
  assert.equal(empty.generation.id,newer);assert.equal(empty.summary.sourceInstances,0);assert.equal(empty.projection.state,'ready');
  ok('source promotion during a build cannot publish backwards; a complete empty import replaces counts with zero');
  const invalid=await install('CO-A',[{...sample('6'),aid:''}]);await assert.rejects(()=>store.build('CO-A','tester'),/identity/);
  assert.equal((await store.read(request)).generation.id,newer);
  await db.query("UPDATE spotlight_import_records SET company_id='CO-B' WHERE run_id=$1",[invalid]);
  await assert.rejects(()=>store.build('CO-A','tester'),/ownership/);
  await db.query('UPDATE spotlight_import_current SET run_id=$1 WHERE tenant_key=$2',[newer,'CO-A']);
  await db.query('DELETE FROM spotlight_import_records WHERE run_id=$1',[second]);await db.query('DELETE FROM spotlight_import_runs WHERE id=$1',[second]);
  assert.equal((await store.read(request)).generation.id,newer);
  ok('invalid source evidence never replaces a good summary; summaries are independent of source pruning');
  const multi=await install('CO-BATCH',Array.from({length:4001},(_,i)=>sample(String(i).padStart(5,'0'))));
  const progress=[];
  assert.equal((await streaming.build('CO-BATCH','tester',{checkpoint:async n=>{progress.push(n);}})).state,'built');
  assert.ok(progress.includes(2000)&&progress.includes(4000));
  assert.equal((await store.read({...request,companyId:'CO-BATCH'})).summary.sourceInstances,4001);
  const realNow=Date.now;
  async function timedBuild(elapsed){
    let offset=0;Date.now=()=>realNow()+offset;
    try{return await streaming.build('CO-BUDGET','tester',{checkpoint:async()=>{offset=elapsed;}});}
    finally{Date.now=realNow;}
  }
  const budget=await install('CO-BUDGET',[sample('budget-1')]);
  assert.equal((await timedBuild(360000)).state,'built','large batch scans can exceed five minutes without enlarging individual query timeouts');
  await install('CO-BUDGET',[sample('budget-2')]);
  await assert.rejects(()=>timedBuild(900001),/fifteen minutes/);
  assert.equal((await store.read({...request,companyId:'CO-BUDGET'})).generation.id,budget);
  ok('large scans retain a fifteen-minute overall deadline and preserve the prior summary when it expires');
  const broken=await install('CO-BATCH',[sample('same')]);
  for(const counts of [[0,0],[2,2],[1,2],[null,1]]){
    await db.query('UPDATE spotlight_import_runs SET expected_count=$2,hydrated_count=$3 WHERE id=$1',[broken,...counts]);
    await assert.rejects(()=>streaming.build('CO-BATCH','tester'),/count|cover/);
    assert.equal((await store.read({...request,companyId:'CO-BATCH'})).generation.id,multi);
  }
  await db.query('UPDATE spotlight_import_runs SET expected_count=2,hydrated_count=2 WHERE id=$1',[broken]);
  await db.query("INSERT INTO spotlight_import_records SELECT run_id,'ZZ-OTHER',company_id,source_id,cve,status,raw FROM spotlight_import_records WHERE run_id=$1",[broken]);
  await assert.rejects(()=>streaming.build('CO-BATCH','tester'),/ownership/);
  assert.equal((await db.query('SELECT count(*)::int n FROM spotlight_summary_generations WHERE run_id=$1',[broken])).rows[0].n,0);
  await db.query("UPDATE spotlight_import_records SET tenant_key='AA-OTHER' WHERE run_id=$1 AND tenant_key='ZZ-OTHER'",[broken]);
  await assert.rejects(()=>streaming.build('CO-BATCH','tester'),/ownership/);
  ok('multi-batch count reconciliation rejects missing/extra records and misplaced tenants sharing source IDs on either side of the valid scope');
  await db.query("UPDATE spotlight_summary_generations SET summary=jsonb_set(summary,'{uniqueCves}','1') WHERE run_id=$1",[newer]);
  assert.equal((await store.read(request)).state,'inconsistent');
  ok('corrupt saved totals fail closed instead of presenting a healthy zero');
  await install('CO-A',[sample('mixed-a'),{...sample('mixed-b'),cid:'b'.repeat(32),status:'closed'}]);
  await store.build('CO-A','tester');
  assert.equal((await store.read(request)).state,'available');
  assert.equal((await store.read({...request,spotlightTenant:'a'.repeat(32)})).state,'inconsistent');
  ok('a second CID in a closed finding blocks registry routing without altering legacy saved-count semantics');
  const local={id:'gone',unresolved:true};
  const localFields={cve:'CS-gone',status:'closed'};
  await install('CO-LOCAL',[local],localFields);
  const localRequest={...request,companyId:'CO-LOCAL',spotlightTenant:'a'.repeat(32)};
  await store.build('CO-LOCAL','tester');
  assert.equal((await store.read(localRequest)).state,'inconsistent','placeholders alone do not prove vendor scope');
  // Use a new completed import with both a vendor record and a local placeholder.
  const nextLocal=await install('CO-LOCAL',[sample('actual')]);
  await db.query('INSERT INTO spotlight_import_records VALUES($1,$2,$2,$3,$4,$5,$6)',
    [nextLocal,'CO-LOCAL',local.id,localFields.cve,localFields.status,local]);
  await db.query('UPDATE spotlight_import_runs SET expected_count=2,hydrated_count=2 WHERE id=$1',[nextLocal]);
  await store.build('CO-LOCAL','tester');
  const localRead=await noRaw.read(localRequest);assert.equal(localRead.state,'available');assert.equal(localRead.summary.sourceInstances,1);
  assert.doesNotMatch(JSON.stringify(localRead),/vendorScope|localPlaceholderRows|aaaaaaaa/);
  const privateScope=(await db.query('SELECT summary->\'vendorScope\' AS scope FROM spotlight_summary_generations WHERE run_id=$1',[nextLocal])).rows[0].scope;
  assert.equal(privateScope.localPlaceholderRows,1);assert.equal(privateScope.missingRows,0);assert.equal(privateScope.rows,2);
  assert.deepEqual((await db.query('SELECT raw FROM spotlight_import_records WHERE run_id=$1 AND source_id=$2',[nextLocal,'gone'])).rows[0].raw,local);
  ok('only exact locally generated placeholders bypass CID checking, preserve counts and never establish tenant scope by themselves');
  for(const raw of [{...local,extra:true},{...local,unresolved:'true'},{...local,cid:null},{...local,status:'closed'},
    {...sample('gone'),cid:undefined,status:'closed',unresolved:true}]) {
    const run=await install('CO-LOOKALIKE',[raw],localFields);await store.build('CO-LOOKALIKE','tester');
    assert.equal((await noRaw.read({...request,companyId:'CO-LOOKALIKE',spotlightTenant:'a'.repeat(32)})).state,'inconsistent');
    const scope=(await db.query('SELECT summary->\'vendorScope\' AS scope FROM spotlight_summary_generations WHERE run_id=$1',[run])).rows[0].scope;
    assert.equal(scope.localPlaceholderRows,0);assert.equal(scope.missingRows,1);
  }
  await install('CO-LOOKALIKE',[local],{...localFields,cve:'CS-other'});await store.build('CO-LOOKALIKE','tester');
  assert.equal((await noRaw.read({...request,companyId:'CO-LOOKALIKE',spotlightTenant:'a'.repeat(32)})).state,'inconsistent');
  ok('extra fields, string booleans, real closed vendor findings and incorrect persisted placeholder identity remain untrusted');

  const recommendation={id:'recommended',action:'Install recommended update'},minimum={id:'minimum',action:'Install minimum update'};
  const patchSample=(id,aid,kev)=>({...sample(id,'CVE-2026-9999',aid),cve:{...sample(id).cve,id:'CVE-2026-9999',is_cisa_kev:kev},
    apps:[{product_name_version:'Test software',remediation_info:{minimum_id:'minimum',recommended_id:'recommended'}}],remediation:{entities:[recommendation,minimum]}});
  const patchRun=await install('CO-PATCH',[patchSample('patch-1','h1',true),patchSample('patch-2','h1',false),patchSample('patch-3','h2',false)]);
  await store.build('CO-PATCH','tester');
  const fixes=(await db.query("SELECT summary->'topFixes' AS fixes FROM spotlight_summary_generations WHERE run_id=$1",[patchRun])).rows[0].fixes;
  assert.equal(fixes.rows.length,1);assert.equal(fixes.rows[0].remediation,'Install recommended update');assert.equal(fixes.rows[0].deviceCount,2);assert.equal(fixes.rows[0].findingCount,3);
  // HIGH severity (3) + CVSS 8 (12) + direct KEV (20). The SQL projection must retain the direct KEV flag.
  assert.equal(fixes.rows[0].maxRisk,35);assert.equal(fixes.missingRemediation,0);
  ok('real SQL projection retains direct KEV risk and recommended-only remediation with device deduplication');
  console.log(JSON.stringify({passed:checks,productionChanges:0}));
} finally {
  await db?.end();await Promise.all(disconnected);if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();
}
