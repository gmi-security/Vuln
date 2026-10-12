// Combined built-application rehearsal. Disposable DB + synthetic identities;
// no production credentials, provider calls or ticket delivery are available.
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {existsSync} from 'node:fs';
import {readFile,realpath,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {encode} from 'next-auth/jwt';
import {loadPlatformReleaseMigrations,applyPlatformReleaseMigrations} from '../lib/db/platform-release-migrations.mjs';
import {loadMigrations,runMigrations} from '../lib/db/migration-runner.mjs';
import {platformCollections,platformBucket} from '../lib/db/platform-records.mjs';
import {readPlatformAuthority} from '../lib/db/platform-authority.mjs';
import {loadConnectorPreview,loadConnectorDraftStore,loadConnectorBindingStore,loadSourceSelection} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
import {executiveHarness} from './executive-report-harness.mjs';
const socket=await realpath(process.argv[2]||'.'),cwd=await realpath('.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket')&&cwd.startsWith('/home/codex/vuln-recovery/'));
assert.ok(existsSync('.next/BUILD_ID'));for(const file of ['.env','.env.local','.env.production','.env.production.local'])assert.equal(existsSync(file),false);
const name='vuln2_release_http_'+randomUUID().replaceAll('-',''),config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000};
const admin=new pg.Client({...config,database:'postgres'});let db,pool,created=false,child,exited,log='',checks=0;
const pass=message=>{checks++;console.log('PASS '+message);};
const url=`postgresql://codex@localhost/${name}?host=${encodeURIComponent(socket)}&port=55483&sslmode=disable`;
const env={PATH:process.env.PATH,NODE_ENV:'production',NEXT_TELEMETRY_DISABLED:'1',DATABASE_URL:url,
 VULN_DISABLE_SCHEDULER:'true',ELASTIC_VULN_ENABLED:'true',VULN_REMEDIATION_UI:'true',VULN_PLATFORM_STORE:'sql',
 VULN_REPORTING_INPUT_REVISIONS:'true',VULN_REPORTING_STORAGE:'published',VULN_REPORTING_WORKER_ENABLED:'true',
 VULN_REPORTING_WORKER_CUSTOMERS:'CO-A,CO-B',VULN_REPORTING_SOURCE_URL:url,VULN_REPORTING_DATABASE_URL:url,
 VULN_REPORTING_SQL_READS:'true',VULN_REPORTING_SQL_CUSTOMERS:'CO-A,CO-B',VULN_REPORTING_EXECUTIVE_ENABLED:'true',
 VULN_TEST_PG_SOCKET:socket+'/.s.PGSQL.55483'};
const run=async(args)=>{
 const p=spawn(process.execPath,args,{env,stdio:['ignore','pipe','pipe']});let output='';
 p.stdout.on('data',v=>output+=v);p.stderr.on('data',v=>output+=v);
 const timer=setTimeout(()=>p.kill('SIGKILL'),120000);try{const [code]=await once(p,'exit');assert.equal(code,0,output);return output;}finally{clearTimeout(timer);}
};
async function stop(){if(!child)return;child.kill();const kill=setTimeout(()=>child?.kill('SIGKILL'),10000);try{await exited;}finally{clearTimeout(kill);child=null;}}
async function start(mode='sql'){
 const reserve=createServer().listen(0,'127.0.0.1');await once(reserve,'listening');const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const base=`http://127.0.0.1:${port}`,secret=randomBytes(32).toString('hex');log='';
 child=spawn(process.execPath,['--require','./tests/shadow-cve-http-network.cjs','node_modules/next/dist/bin/next','start','-H','127.0.0.1','-p',String(port)],
  {env:{...env,VULN_PLATFORM_STORE:mode,NEXTAUTH_URL:base,NEXTAUTH_SECRET:secret},stdio:['ignore','pipe','pipe']});exited=once(child,'exit');
 child.stdout.on('data',v=>log=(log+v).slice(-128000));child.stderr.on('data',v=>log=(log+v).slice(-128000));
 let ready=false;for(const deadline=Date.now()+60000;Date.now()<deadline;){try{if((await fetch(base+'/login',{signal:AbortSignal.timeout(1000)})).ok){ready=true;break;}}catch{}await delay(100);}assert.ok(ready,log);
 const token=await encode({secret,token:{name:'Isolated release member',orgMember:true,orgRole:'MEMBER'},maxAge:300});
 return async(path,{method='GET',body,anonymous=false}={})=>{
  const response=await fetch(base+path,{method,headers:{...(anonymous?{}:{cookie:`next-auth.session-token=${token}`}),origin:base,'content-type':'application/json'},
   ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)});
  const text=await response.text();return {status:response.status,value:response.headers.get('content-type')?.includes('json')?JSON.parse(text):text};
 };
}
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:3});
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb NOT NULL,updated_at timestamptz DEFAULT now());CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY)');
 await applyPlatformReleaseMigrations(db,await loadPlatformReleaseMigrations());await runMigrations(pool,await loadMigrations(new URL('../db/migrations/',import.meta.url)));
 const when=new Date().toISOString(),runId=randomUUID(),tenant=randomUUID();
 const company=id=>({id,name:'Release fixture '+id,kind:'client',industry:'Test',createdAt:when,contactName:'',contactEmail:''});
 const findings=Array.from({length:3},(_,i)=>({id:'F-'+i,companyId:'CO-A',companyName:'Release fixture CO-A',connector:'defender',cve:'CVE-2026-1234',
  title:'Fixture vulnerability',asset:'fixture-host-'+i,severity:'High',cvss:8.1,realRisk:70,status:'Open',assignee:null,firstSeen:when,lastSeen:when,
  remediation:'Install fixture update',defender:{deviceId:'device-'+i,hostname:'fixture-host-'+i,runId,observedAt:when,active:true,cvss:8.1}}));
 const scan={id:'defender:CO-A',companyId:'CO-A',companyName:'Release fixture CO-A',connector:'defender',externalRef:runId,
  name:'Fixture Defender assessment',status:'Completed',findingsCount:3,createdAt:when,completedAt:when,targets:[]};
 const data={companies:['CO-A','CO-B'].map(id=>[id,company(id)]),folders:[],scans:[[scan.id,scan]],assets:[],findings:findings.map(f=>[f.id,f]),
  compensatingControls:[],identityAliases:[],counter:1000,settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},
  meta:{autoSyncDefaultMigrated:true,defenderGenerations:{'CO-A':runId}},reportingKevCatalog:(await executiveHarness()).threat.reportingKevCatalog()};
 for(const [kind,c]of Object.entries(platformCollections))for(let b=0;b<c.buckets;b++)await db.query('INSERT INTO vuln_store(key,data) VALUES($1,$2)',
  [`${kind}:${String(b).padStart(2,'0')}`,JSON.stringify(data[kind].filter(([id])=>platformBucket(id,c.buckets)===b))]);
 await db.query("INSERT INTO vuln_store(key,data) VALUES('meta',$1)",[JSON.stringify(Object.fromEntries(Object.entries(data).filter(([k])=>!platformCollections[k])))]);
 await run(['scripts/platform-store-transition.mjs','--to-sql','--writers-stopped','--expect-epoch','1','--expect-revision','0']);
 await db.query('CREATE TABLE defender_connections(company_id text PRIMARY KEY,tenant_id text,revision int)');
 await db.query('INSERT INTO defender_connections VALUES($1,$2,1)',['CO-A',tenant]);
 // Real review services, explicitly synthetic source identity. No operational
 // import route is approved and no production assignment is represented.
 const preview=await loadConnectorPreview(),collect=async()=>preview({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env);
 const drafts=(await loadConnectorDraftStore())(pool),bindings=(await loadConnectorBindingStore())(pool),selections=(await loadSourceSelection()).createSourceSelectionStore(pool);
 await drafts.importPreview((await collect()).fingerprint,'private-http-fixture',collect);
 const request=structuredClone((await bindings.list('CO-A',collect)).items.find(i=>i.provider==='defender').assignmentRequest);
 Object.assign(request,{decision:'reviewed',note:'Synthetic HTTP test only',proposal:{companyId:'CO-A',tenantId:tenant,authority:'findings-primary',datasets:[],targets:[]}});
 await bindings.save(request,'private-http-fixture',collect);
 for(const id of ['CO-A','CO-B']){const review=(await selections.exportCustomer(id,collect)).reviewRequest;review.note='Synthetic HTTP test only';await selections.save(review,'private-http-fixture',collect);}
 // Legacy application creates this separate history table on startup; the
 // dedicated worker must also have it during the offline warm-up rehearsal.
 await db.query('CREATE TABLE vuln_metrics_history(id bigserial PRIMARY KEY,company_id text,ts timestamptz,data jsonb)');
 for(let i=0;i<2;i++)await run(['scripts/customer-reporting-worker.mjs','--once']);
 let requestHttp=await start();
 assert.equal((await requestHttp('/api/findings/F-0',{anonymous:true})).status,401);
 const reportPath='/api/elastic-dashboard/reporting?companyId=CO-A&view=sections';
 let response=await requestHttp(reportPath);assert.equal(response.status,200,JSON.stringify(response.value));assert.equal(response.value.model.metrics.vulnerabilities.open,3);assert.ok(response.value.savedReport.capturedAt);
 const empty=await requestHttp(reportPath.replace('CO-A','CO-B'));assert.equal(empty.status,200,JSON.stringify(empty.value));assert.equal(empty.value.model.metrics.vulnerabilities.open,0);
 pass('installed SQL authority serves authenticated saved customer reports and a distinct empty customer');
 response=await requestHttp('/api/findings/F-0',{method:'PATCH',body:{status:'Resolved',assignee:'Fixture patch team'}});assert.equal(response.status,200,JSON.stringify(response.value));
 const row=(await db.query("SELECT payload FROM app_findings WHERE id='F-0'")).rows[0].payload;assert.equal(row.status,'Resolved');assert.equal(row.assignee,'Fixture patch team');
 const commit=(await db.query("SELECT counts FROM app_store_commits WHERE operation='save' ORDER BY epoch DESC,revision DESC LIMIT 1")).rows[0].counts;assert.equal(commit.updated,1);
 assert.equal((await requestHttp(reportPath)).status,503);await run(['scripts/customer-reporting-worker.mjs','--once']);
 response=await requestHttp(reportPath);assert.equal(response.status,200,JSON.stringify(response.value));assert.equal(response.value.model.metrics.vulnerabilities.open,2);
 pass('actual analyst PATCH waits for one-row SQL commit; old report is withheld until the worker publishes its replacement');
 await stop();requestHttp=await start();response=await requestHttp('/api/findings/F-0');assert.equal(response.status,200,JSON.stringify(response.value));assert.equal(response.value.finding.status,'Resolved');
 pass('application restart retains the committed analyst decision');
 await stop();const a=await readPlatformAuthority(db);
 await run(['scripts/platform-store-transition.mjs','--to-legacy','--writers-stopped','--expect-epoch',a.epoch,'--expect-revision',a.revision]);
 requestHttp=await start('legacy');response=await requestHttp('/api/findings/F-0');assert.equal(response.status,200,JSON.stringify(response.value));assert.equal(response.value.finding.status,'Resolved');assert.equal(response.value.finding.assignee,'Fixture patch team');
 pass('operator reverse command and compatible legacy restart retain post-cutover edits');
 console.log(JSON.stringify({checks,passed:true,realProviderCalls:0,realTickets:0}));
}catch(error){await writeFile('platform-release-http-failure.log',log,{mode:0o600});throw error;}
finally{await stop();await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);await admin.end();}
