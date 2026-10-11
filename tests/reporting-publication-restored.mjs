// Read-only retained snapshot -> disposable application DB -> actual bounded
// worker -> saved reader -> independent legacy reference. Reviews use clearly
// synthetic connection identities; they do NOT approve live customer ownership.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {createReportingInputDigests,publishReportingInputRevisions,reportingKeys} from '../lib/db/customer-reporting-revisions.mjs';
import {buildCustomerReportingSections,readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {loadConnectorPreview,loadConnectorDraftStore,loadConnectorBindingStore,loadSourceSelection} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
import {originalSections,originalExecutive} from './reporting-restored-reference.mjs';
import {executiveHarness} from './executive-report-harness.mjs';
import {readPlatformAuthority} from '../lib/db/platform-authority.mjs';
import {transitionPlatformStore} from '../lib/db/platform-store.mjs';
import {prepareCapacityFixture} from './platform-capacity-fixture.mjs';

globalThis.fetch=()=>{throw Error('No provider or ticket calls allowed');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_reporting_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
const scope=['CO-230784','CO-147284','CO-REPORT-EMPTY'],labels=['Retained Defender','Retained mixed scanners','Empty fixture'];
const sqlAuthority=process.env.VULN_TEST_SQL_AUTHORITY==='true';
let source,db,pool,created=false,child,exited,retainedHashes;
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 source=new pg.Client({...config,database:'recovery_application'});db=new pg.Client({...config,database:name});
 await source.connect();await db.connect();pool=new pg.Pool({...config,database:name,max:4});
 for(const file of ['customer-connector-drafts','customer-connector-bindings','customer-source-selections','customer-reporting-inputs','customer-reporting-buckets','customer-reporting-sections','customer-reporting-jobs','customer-reporting-executive'])
  await db.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb,updated_at timestamptz DEFAULT now());CREATE TABLE vuln_metrics_history(id bigserial PRIMARY KEY,company_id text,ts timestamptz,data jsonb)');
 await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await db.query('BEGIN');
 const digests=createReportingInputDigests(),copyStarted=Date.now(),observed=new Map();let bytes=0;
 const offlineCatalog=(await executiveHarness()).threat.reportingKevCatalog();
 for(const key of [...reportingKeys,...(sqlAuthority?['folders:00']:[])]){
  assert.ok(Date.now()-copyStarted<300000,'Copy deadline');
  let json=(await source.query('SELECT data::text AS json FROM vuln_store WHERE key=$1',[key])).rows[0].json;
  bytes+=Buffer.byteLength(json);
  if(key==='meta'){const m=JSON.parse(json);m.reportingKevCatalog=offlineCatalog;json=JSON.stringify(m);}
  if(key==='companies:00'){const companies=JSON.parse(json);assert.ok(!companies.some(r=>r[0]===scope[2]));companies.push([scope[2],{id:scope[2],name:'Empty reporting fixture',industry:'Fixture'}]);json=JSON.stringify(companies);}
  if(/^(findings|scans|assets):/.test(key))for(const [,r] of JSON.parse(json))if(scope.includes(r.companyId)){
   const kind=key.split(':')[0],values=kind==='findings'?[['findings',r.connector],...(r.seenBy??[]).map(s=>['seenBy',s]),...(r.enrichments??[]).map(e=>['enrichment',e.source])]:[[kind,kind==='scans'?r.connector:r.source]];
   for(const [role,provider] of values){const k=JSON.stringify([scope.indexOf(r.companyId),role,/^[a-z]+$/.test(provider)?provider:'invalid']);observed.set(k,(observed.get(k)??0)+1);}
  }
  await db.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',[key,json]);await digests.bucket(key,json);
 }
 const inputs=digests.finish();await publishReportingInputRevisions(db,inputs);
 const history=(await source.query('SELECT company_id,ts,data FROM vuln_metrics_history WHERE company_id=ANY($1::text[]) ORDER BY ts,id LIMIT 10001',[scope])).rows;
 assert.ok(history.length<=10000);for(const h of history)await db.query('INSERT INTO vuln_metrics_history(company_id,ts,data) VALUES($1,$2,$3)',[h.company_id,h.ts,h.data]);
 await db.query('COMMIT');await source.query('COMMIT');
 const bucketCounts=inputs.map(i=>i.buckets.filter(p=>p[0].startsWith('findings:')).length);
 console.log(JSON.stringify({phase:'private-copy',retainedCustomers:inputs.length-1,serializedBytes:bytes,copyMs:Date.now()-copyStarted,
  findingsBucketDistribution:{empty:bucketCounts.filter(n=>n===0).length-1,oneToEight:bucketCounts.filter(n=>n>0&&n<=8).length,nineToSixtyFour:bucketCounts.filter(n=>n>8).length}}));
 console.log(JSON.stringify({phase:'retained-source-roles',counts:[...observed].map(([k,n])=>[...JSON.parse(k),n])}));
 if(sqlAuthority){
  await db.query("SET statement_timeout='60s'");
  retainedHashes=(await db.query('SELECT key,md5(data::text) hash FROM vuln_store ORDER BY key')).rows;
  for(const file of ['001_core_storage.sql','002_platform_store_authority.sql'])await db.query(await readFile('db/migrations/'+file,'utf8'));
  const started=Date.now(),reporting=createReportingInputDigests();await db.query('BEGIN');
  await db.query("SET LOCAL statement_timeout='60s';SET LOCAL idle_in_transaction_session_timeout='90s'");
  const result=await transitionPlatformStore(db,'sql',await readPlatformAuthority(db),{actor:'retained-verification',reporting});
  await publishReportingInputRevisions(db,reporting.finish());await db.query('COMMIT');
  // Transition independently compares every copied payload, including sources
  // outside the three reporting cohorts. No row/sample-only parity claim.
  console.log(JSON.stringify({phase:'retained-sql-cutover',counts:result.counts,elapsedMs:Date.now()-started}));
 }

 // Only synthetic configuration metadata is installed; no real keys/config are
 // copied from production or the restore. Real review stores validate requests.
 await db.query('CREATE TABLE defender_connections(company_id text,tenant_id text,revision int)');
 await db.query('INSERT INTO defender_connections VALUES($1,$2,1)',[scope[0],'fixture-defender-tenant']);
 const metadata=await readApplicationConnectorMetadata(db),atlas=metadata.companies.find(c=>c.id===scope[1]);assert.ok(atlas);
 const env={FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:atlas.name,
  SPIDERFOOT_URL:'https://fixture.invalid',MISP_URL:'https://fixture.invalid',MISP_API_KEY:'fixture',OPENCTI_URL:'https://fixture.invalid',OPENCTI_API_KEY:'fixture',
  TIDAL_EMAIL:'fixture@example.invalid',TIDAL_PASSWORD:'fixture',AUTOMATE_BASE_URL:'https://fixture.invalid',AUTOMATE_API_CLIENT_ID:'fixture',AUTOMATE_USERNAME:'fixture',AUTOMATE_PASSWORD:'fixture'};
 const preview=await loadConnectorPreview(),api=await loadSourceSelection();
 const collect=async()=>preview({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env);
 const drafts=(await loadConnectorDraftStore())(pool),bindings=(await loadConnectorBindingStore())(pool),selections=api.createSourceSelectionStore(pool);
 await drafts.importPreview((await collect()).fingerprint,'test:retained-reporting',collect);
 for(const id of scope){
  const sources=id===scope[0]?['defender','tidal','automate','misp','opencti']:id===scope[1]?['crowdstrike','spiderfoot','automate','misp','opencti']:[];
  for(const provider of sources){
   const request=structuredClone((await bindings.list(id,collect)).items.find(i=>i.provider===provider).assignmentRequest);
   Object.assign(request,{decision:'reviewed',note:'Synthetic review for retained-data mechanics; no live ownership acceptance',proposal:{companyId:id,
    tenantId:provider==='defender'?'fixture-defender-tenant':provider==='crowdstrike'?'a'.repeat(32):['tidal','automate'].includes(provider)?`fixture-${id}`:null,
    authority:['misp','opencti'].includes(provider)?'enrichment':['tidal','automate'].includes(provider)?'inventory':'findings-primary',datasets:[],targets:provider==='spiderfoot'?['fixture.invalid']:[]}});
   await bindings.save(request,'test:retained-reporting',collect);
  }
  const review=(await selections.exportCustomer(id,collect)).reviewRequest;review.note='Synthetic retained-reporting review only';await selections.save(review,'test:retained-reporting',collect);
  assert.equal((await api.readSourceSelectionStatus(db,id,await collect())).state,'reviewed');
 }
 const u=new URL(`postgresql://codex@localhost/${name}`);u.searchParams.set('host',socket);u.searchParams.set('port','55483');
 const workerScope=sqlAuthority?await prepareCapacityFixture(db):scope;
 if(sqlAuthority){
  const runtime=spawn(process.execPath,['--max-old-space-size=4096','--experimental-vm-modules','tests/platform-retained-runtime.mjs',socket,name],{stdio:['ignore','pipe','pipe']});
  runtime.stdout.on('data',v=>process.stdout.write(v));runtime.stderr.on('data',v=>process.stderr.write(v));
  const code=await new Promise((resolve,reject)=>{runtime.once('error',reject);runtime.once('close',resolve);});assert.equal(code,0,'Full retained runtime check failed');
 }
 let output='',errors='';const started=Date.now();
 child=spawn(process.execPath,['--max-old-space-size=512','scripts/customer-reporting-worker.mjs'],{env:{PATH:process.env.PATH,
  VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:workerScope.join(','),VULN_REPORTING_STORAGE:'published',VULN_REPORTING_INPUT_REVISIONS:'true',VULN_REPORTING_EXECUTIVE_ENABLED:'true',
  DATABASE_URL:u.href,VULN_REPORTING_SOURCE_URL:u.href,VULN_REPORTING_DATABASE_URL:u.href},stdio:['ignore','pipe','pipe']});
 child.stdout.on('data',v=>output+=v);child.stderr.on('data',v=>errors+=v);
 exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
 while((await db.query("SELECT count(*)::int n FROM customer_reporting_jobs WHERE state='succeeded'")).rows[0].n<workerScope.length){
  assert.equal(child.exitCode,null,'Worker exited before all reports finished');assert.ok(Date.now()-started<600000,'Whole-customer refresh must leave headroom below fifteen-minute expiry');
  const failed=(await db.query("SELECT company_id FROM customer_reporting_jobs WHERE state IN ('retry','failed')")).rows[0];
  if(failed){
   child.kill('SIGTERM');await exited;const a=await pool.connect(),b=await pool.connect();
   try{await buildCustomerReportingSections(a,b,failed.company_id,(await loadReportingSections()).bundle,{mode:'published',requireExecutive:true});}
   finally{a.release();b.release();}
   assert.fail('Retained worker failed despite a successful direct diagnostic build');
  }
  await delay(250);
 }
 child.kill('SIGTERM');const finish=await exited;assert.equal(finish.code,0,errors);const cycleMs=Date.now()-started;
 const events=output.trim().split('\n').map(l=>JSON.parse(l)),ticks=events.filter(e=>e.state==='succeeded');assert.equal(ticks.length,workerScope.length);
 if(sqlAuthority){
  const totals=await db.query('SELECT company_id,count(*)::int n FROM app_findings GROUP BY company_id');
  const counts=new Map(totals.rows.map(r=>[r.company_id,r.n]));
  for(const id of workerScope){const a=await pool.connect(),b=await pool.connect();try{
   const revision=(await db.query('SELECT revision FROM customer_source_selections WHERE company_id=$1',[id])).rows[0].revision;
   const report=await readCustomerReportingSections(a,b,id,{mode:'published',requireExecutive:true,expectedReviewRevision:revision});
   assert.equal(report.state,'available');assert.equal(report.records,counts.get(id)??0);assert.equal(report.executive.company.id,id);
  }finally{a.release();b.release();}}
  console.log(JSON.stringify({phase:'all-customer-capacity',customers:workerScope.length,cycleMs,verifiedRecords:totals.rows.reduce((n,r)=>n+r.n,0)}));
 }
 assert.equal(ticks.find(t=>t.companyId===scope[2]).bucketsRead,0);
 const {reference}=await loadReportingSections();
 for(let i=0;i<scope.length;i++){
  const id=scope[i],review=await api.readSourceSelectionStatus(db,id,await collect()),times=[];let result;
  for(let n=0;n<5;n++){
   const a=await pool.connect(),b=await pool.connect(),start=performance.now();
   try{result=await readCustomerReportingSections(a,b,id,{mode:'published',expectedReviewRevision:review.revision,requireExecutive:true});}
   finally{a.release();b.release();}times.push(Math.round((performance.now()-start)*10)/10);
  }
  assert.equal(result.state,'available');const expected=await originalSections(db,reference,id,result.capturedAt);
  assert.deepEqual(result.model,JSON.parse(JSON.stringify(expected.model)));assert.equal(result.records,expected.records);
  assert.deepEqual(result.executive,await originalExecutive(db,id,result.capturedAt));
  const tick=ticks.find(t=>t.companyId===id);
  console.log(JSON.stringify({cohort:labels[i],records:result.records,open:result.model.metrics.vulnerabilities.open,
   findingsSources:expected.contributors,buildMs:tick.buildMs,bucketsRead:tick.bucketsRead,readMs:times}));
 }
 const stopped=events.find(e=>e.event==='stopped');console.log(JSON.stringify({cycleMs,peakWorkerRssMiB:stopped.peakRssMiB,sourceCalls:0,
  reviewEvidence:'synthetic connection identities, not live source ownership acceptance'}));
 console.log('PASS published worker, reviewed-source checks, indexed builds and saved reads preserve full retained report parity');
 if(sqlAuthority){
  const started=Date.now(),reporting=createReportingInputDigests();await db.query('BEGIN');
  const reverse=await transitionPlatformStore(db,'legacy',await readPlatformAuthority(db),{actor:'retained-reverse-verification',reporting});
  await publishReportingInputRevisions(db,reporting.finish());await db.query('COMMIT');
  assert.deepEqual((await db.query('SELECT key,md5(data::text) hash FROM vuln_store ORDER BY key')).rows,retainedHashes);
  console.log(JSON.stringify({phase:'retained-reverse',elapsedMs:Date.now()-started,counts:reverse.counts,verifiedBuckets:retainedHashes.length}));
 }
}finally{
 if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await exited.catch(()=>{});}
 await source?.end();await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();
}
