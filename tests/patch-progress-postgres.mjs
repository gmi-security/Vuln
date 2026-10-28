// Explicit disposable Unix-socket database only. No production configuration is loaded.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve,dirname,extname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import pg from 'pg';
const host=process.env.PATCH_PROGRESS_TEST_SOCKET,database=process.env.PATCH_PROGRESS_TEST_DATABASE;
assert.match(host||'',/^\/home\/codex\/vuln-recovery\/.+\/socket$/);assert.match(database||'',/^patch_progress_test_[a-f0-9]+$/);
const db=new pg.Pool({host,port:55483,database,user:'codex',max:1,statement_timeout:15000,connectionTimeoutMillis:5000});
const cid='a'.repeat(32),company='CO-A',cve='CVE-2026-100202',run='11111111-1111-4111-8111-111111111111',csRun='22222222-2222-4222-8222-222222222222',binding='b'.repeat(64);
const route={companyId:company,sourceScope:'55',candidateId:'candidate',connectionRef:'nessus-server',revision:1,bindingRevision:1,targets:['10.0.0.0/24']};
let reviewedSpotlight=true;
const stubs={persist:{applicationDatabase:()=>db},'elastic-dashboard':{DashboardError:class extends Error{}},'customer-scanner-routing-server':{loadReviewedScannerRoutes:async()=>[route]},
 'customer-spotlight-routing-server':{loadReviewedSpotlightRoutes:async()=>reviewedSpotlight?[{companyId:company,sourceScope:cid,bindingKey:binding}]:null},
 'spotlight-summary-model':{matchesSpotlightTenant:(s,id,n)=>s?.version===2&&s.tenantId===id&&s.rows===Number(n)&&s.missingRows===0&&!s.mixed}};
async function load(entry){const cache=new Map();function read(path){path=resolve(path);if(cache.has(path))return cache.get(path);const m=new SourceTextModule(ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,m);return m;}const m=read(entry);await m.link(async(s,p)=>{const stub=stubs[s.split('/').at(-1)];if(!stub&&s.startsWith('.'))return read(resolve(dirname(p.identifier),s+(extname(s)?'':'.ts')));const v=stub||await import(s);return new SyntheticModule(Object.keys(v),function(){for(const k of Object.keys(v))this.setExport(k,v[k]);});});await m.evaluate();return m.namespace;}
try{
 await db.query(readFileSync('db/migrations/001_core_storage.sql','utf8'));
 await db.query(readFileSync('docs/sql/patch-progress.sql','utf8'));
 await db.query(`CREATE TABLE app_store_metadata(id int primary key,payload jsonb);
 CREATE TABLE defender_connections(company_id text primary key,current_run uuid,revision int);
 CREATE TABLE defender_import_runs(id uuid primary key,company_id text,revision int,status text,finished_at timestamptz,summary jsonb);
 CREATE TABLE defender_devices(run_id uuid,device_id text,record jsonb,primary key(run_id,device_id));
 CREATE TABLE defender_records(run_id uuid,device_id text,cve text);
 CREATE TABLE customer_spotlight_routes(company_id text,provider text,enabled boolean,source_scope text);
 CREATE TABLE spotlight_import_current(tenant_key text,run_id uuid);
 CREATE TABLE spotlight_import_runs(id uuid,tenant_key text,status text,started_at timestamptz,finished_at timestamptz,expected_count int,hydrated_count int,checkpoint_version int);
 CREATE TABLE spotlight_import_run_scopes(run_id uuid,company_id text,cid text,binding_key text);
 CREATE TABLE spotlight_import_records(run_id uuid,tenant_key text,company_id text,source_id text,cve text,status text,raw jsonb);
 CREATE TABLE spotlight_summary_current(company_id text,run_id uuid,model_version int);
 CREATE TABLE spotlight_summary_generations(company_id text,run_id uuid,model_version int,summary jsonb,source_completed_at timestamptz,source_rows int);`);
 for(const id of [company,'CO-B'])await db.query('INSERT INTO app_companies(id,payload) VALUES($1,$2)',[id,JSON.stringify({id,name:id})]);
 await db.query('INSERT INTO app_store_metadata VALUES(1,$1)',[JSON.stringify({meta:{defenderGenerations:{[company]:run}}})]);
 await db.query('INSERT INTO defender_connections VALUES($1,$2,1)',[company,run]);
 await db.query("INSERT INTO defender_import_runs VALUES($1,$2,1,'succeeded','2026-10-22T00:00:00.123Z',$3)",[run,company,JSON.stringify({findings:1})]);
 for(const asset of ['a','b']){
  await db.query('INSERT INTO defender_devices VALUES($1,$2,$3)',[run,asset,JSON.stringify({deviceId:asset,lastSeen:'2026-10-21T00:00:00Z'})]);
  const f={id:'f'+asset,companyId:company,asset,cve,connector:'defender',status:asset==='a'?'Open':'Resolved',defender:{deviceId:asset,runId:run,active:asset==='a',observedAt:'2026-10-22T00:00:00.123Z'},seenBy:['defender']};
  await db.query('INSERT INTO app_findings(id,company_id,connector,status,cve,asset,payload) VALUES($1,$2,$3,$4,$5,$6,$7)',[f.id,company,f.connector,f.status,cve,asset,JSON.stringify(f)]);
 }
 await db.query('INSERT INTO defender_records VALUES($1,$2,$3)',[run,'a',cve]);
 const scan={id:'scan',companyId:company,connector:'defender',status:'Completed',completedAt:'2026-10-22T00:00:00.123Z'};
 await db.query('INSERT INTO app_scans(id,company_id,connector,status,created_at,payload) VALUES($1,$2,$3,$4,now(),$5)',[scan.id,company,scan.connector,scan.status,JSON.stringify(scan)]);
 const model=await load('lib/patch-progress.ts'),sources=await load('lib/patch-progress-sources.ts'),store=await load('lib/patch-progress-store.ts');
 const ticket={id:'33333333-3333-4333-8333-333333333333',kind:'group',companyId:company,ticketId:12,hostCount:2,createdAt:'2026-10-20T00:00:00Z',scopeHash:'scope',packet:{appCompanyId:company,source:'stored-findings',connectors:['defender'],cves:[cve],reviewRows:['a','b'].map(asset=>({asset,cve,findingId:'f'+asset}))}};
 const scope=model.progressScope(ticket),collection=await sources.collectPatchProgress(db,scope);
 assert.deepEqual(collection.rows.map(r=>r.state),['detected','clear']);
 await store.recordProgressAttempt(db,scope);await store.saveProgressCollection(db,scope,collection);
 let read=await store.readPatchProgress(db,company);assert.deepEqual(read.tickets[0].summary,{devices:2,detected:1,clear:1,unknown:0,reappeared:0,pairs:2});
 assert.equal((await store.readPatchProgress(db,'CO-B')).tickets.length,0);
 assert.equal((await store.readPatchProgress(db,'CO-B',{requestId:ticket.id,kind:'group'})).rows.length,0);
 await store.saveProgressCollection(db,scope,collection);assert.equal(Number((await db.query('SELECT count(*) n FROM patch_progress_evaluations')).rows[0].n),1);
 const next={...collection,fingerprint:'next',capturedAt:'2030-01-01T00:00:00Z',rows:collection.rows.map(r=>({...r,state:'detected'}))};
 await store.recordProgressAttempt(db,scope);await store.saveProgressCollection(db,scope,next);
 read=await store.readPatchProgress(db,company);assert.equal(read.tickets[0].summary.reappeared,1);
 await assert.rejects(store.saveProgressCollection(db,scope,{...collection,fingerprint:'stale'}),/newer completed/);
 console.log('PASS published Defender comparison, original scope, reappearance, idempotency, customer isolation and stale-writer refusal');
 // Real SQL + bounded 500-row writes. Abort after staging and verify readers retain the last complete result.
 const bigScope={...scope,ticket:{...ticket,id:'44444444-4444-4444-8444-444444444444',hostCount:10001}};
 const large={...collection,fingerprint:'large',capturedAt:'2030-01-01T00:00:00Z',rows:Array.from({length:10001},(_,i)=>({...collection.rows[0],key:'k'+i,deviceKey:'d'+i,hostId:'h'+i}))};
 await store.recordProgressAttempt(db,bigScope);let chunks=0;
 const failing={connect:()=>db.connect(),query:async(sql,p)=>{if(sql.includes('INSERT INTO patch_progress_observations')&&++chunks===2)throw Error('simulated stop');return db.query(sql,p);}};
 await assert.rejects(store.saveProgressCollection(failing,bigScope,large),/simulated stop/);
 assert.equal((await store.readPatchProgress(db,company)).tickets.find(t=>t.requestId===bigScope.ticket.id).summary,null);
 await store.saveProgressCollection(db,bigScope,large);
 const detail=await store.readPatchProgress(db,company,{requestId:bigScope.ticket.id,kind:'group'});assert.equal(detail.rows.length,100);assert.equal(detail.hasMore,true);
 assert.equal((await store.readPatchProgress(db,company,{requestId:bigScope.ticket.id,kind:'group',detailOffset:10000})).rows.length,1);
 console.log('PASS interrupted 10,001-device staging/retry and bounded detail pagination');
 const client=await db.connect();let trends;try{trends=await sources.collectProgressTrends(client,company);}finally{client.release();}
 assert.equal(trends.find(t=>t.source==='total').count,1);await store.saveProgressTrends(db,company,trends);
 assert.equal((await store.readPatchProgress(db,company)).trends.find(t=>t.source==='total').count,1);
 console.log('PASS connector-independent SQL open-count history');
 await db.query(`CREATE FUNCTION reject_progress_source() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source='test-failure' THEN RAISE EXCEPTION 'simulated source failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER reject_progress_source BEFORE INSERT ON patch_progress_trends FOR EACH ROW EXECUTE FUNCTION reject_progress_source()`);
 await assert.rejects(store.saveProgressTrends(db,company,[{source:'total',generation:'atomic-test',observedAt:'2026-10-28',count:10,unit:'test'},{source:'test-failure',generation:'atomic-test',observedAt:'2026-10-28',count:10,unit:'test'}]),/simulated source failure/);
 assert.equal(Number((await db.query("SELECT count(*) n FROM patch_progress_trends WHERE generation='atomic-test'")).rows[0].n),0,'a failed source write must not expose a partial trend observation');
 await db.query('DROP TRIGGER reject_progress_source ON patch_progress_trends; DROP FUNCTION reject_progress_source()');
 console.log('PASS total and source trend counts publish atomically');
 const regressionFailures=[];
 async function regression(name,fn){try{await fn();console.log('PASS '+name);}catch(e){regressionFailures.push(name+': '+e.message);console.error('FAIL '+name,e.message);}}
 await regression('Defender historical verification survives later imports and pruning, but not a return or a scope change',async()=>{
  const newerRun='88888888-8888-4888-8888-888888888888';
  const original=(await db.query("SELECT payload FROM app_findings WHERE id='fb'")).rows[0].payload;
  const retainedScope=model.progressScope({...ticket,id:'77777777-7777-4777-8777-777777777777',hostCount:1,packet:{...ticket.packet,reviewRows:[{asset:'b',cve,findingId:'fb'}]}});
  async function current(id){await db.query('UPDATE defender_connections SET current_run=$1',[id]);await db.query('UPDATE app_store_metadata SET payload=$1',[JSON.stringify({meta:{defenderGenerations:{[company]:id}}})]);}
  try{
   await db.query("INSERT INTO defender_import_runs VALUES($1,$2,1,'succeeded','2026-10-25T00:00:00Z','{}')",[newerRun,company]);
   await db.query('INSERT INTO defender_devices VALUES($1,$2,$3)',[newerRun,'b',JSON.stringify({deviceId:'b',lastSeen:'2026-10-21T00:00:00Z'})]);await current(newerRun);
   let result=await sources.collectPatchProgress(db,retainedScope);
   assert.equal(result.rows[0].state,'clear');assert.equal(result.rows[0].retained,true);assert.equal(result.rows[0].generation,run);
   assert.equal(result.rows[0].assessmentAt,'2026-10-21T00:00:00Z');
   assert.equal((await sources.collectPatchProgress(db,{...retainedScope,ticket:{...retainedScope.ticket,createdAt:'2026-10-23'}})).rows[0].state,'unknown','an earlier fix cannot verify a later ticket');
   await db.query('UPDATE defender_import_runs SET company_id=$1 WHERE id=$2',['CO-B',run]);
   assert.equal((await sources.collectPatchProgress(db,retainedScope)).rows[0].state,'unknown');
   await db.query('UPDATE defender_import_runs SET company_id=$1 WHERE id=$2',[company,run]);
   await db.query('INSERT INTO defender_records VALUES($1,$2,$3)',[run,'b',cve]);
   assert.equal((await sources.collectPatchProgress(db,retainedScope)).rows[0].state,'unknown','a resolved label cannot override a source positive');
   await db.query("DELETE FROM defender_records WHERE run_id=$1 AND device_id='b'",[run]);
   await store.recordProgressAttempt(db,retainedScope);await store.saveProgressCollection(db,retainedScope,result);
   await db.query("DELETE FROM defender_devices WHERE run_id=$1 AND device_id='b'",[run]);
   result=await sources.collectPatchProgress(db,retainedScope);assert.equal(result.rows[0].state,'clear','in-flight pruning must retain proof');
   await store.saveProgressCollection(db,retainedScope,result);
   await db.query('DELETE FROM defender_import_runs WHERE id=$1',[run]);
   result=await sources.collectPatchProgress(db,retainedScope);assert.equal(result.rows[0].state,'clear');
   await store.saveProgressCollection(db,retainedScope,result);
   assert.equal(Number((await db.query('SELECT count(*) n FROM patch_progress_evaluations WHERE request_id=$1',[retainedScope.ticket.id])).rows[0].n),1,'retained proof must be idempotent');
   await db.query("UPDATE defender_import_runs SET status='running' WHERE id=$1",[newerRun]);
   await assert.rejects(sources.collectPatchProgress(db,retainedScope),/publication/i,'an incomplete publication must not replace the saved verification');
   await db.query("UPDATE defender_import_runs SET status='succeeded' WHERE id=$1",[newerRun]);
   assert.equal((await sources.collectPatchProgress(db,retainedScope)).rows[0].state,'clear');
   assert.equal((await sources.collectPatchProgress(db,{...retainedScope,ticket:{...retainedScope.ticket,scopeHash:'other'}})).rows[0].state,'unknown');
   assert.equal((await sources.collectPatchProgress(db,{...retainedScope,ticket:{...retainedScope.ticket,companyId:'CO-B'}})).rows[0].state,'unknown');
   await db.query('UPDATE defender_connections SET revision=2');
   await assert.rejects(sources.collectPatchProgress(db,retainedScope),/publication/i);await db.query('UPDATE defender_connections SET revision=1');
   await db.query('INSERT INTO defender_records VALUES($1,$2,$3)',[newerRun,'b',cve]);
   assert.notEqual((await sources.collectPatchProgress(db,retainedScope)).rows[0].state,'clear','even a stale source positive must prevent retaining clearance');
   await db.query("UPDATE defender_devices SET record=$1 WHERE run_id=$2 AND device_id='b'",[JSON.stringify({deviceId:'b',lastSeen:'2026-10-24T00:00:00Z'}),newerRun]);
   await db.query("UPDATE app_findings SET payload=$1 WHERE id='fb'",[JSON.stringify({...original,defender:{...original.defender,active:true,runId:newerRun,observedAt:'2026-10-25T00:00:00Z'}})]);
   result=await sources.collectPatchProgress(db,retainedScope);assert.equal(result.rows[0].state,'detected');await store.saveProgressCollection(db,retainedScope,result);
   assert.equal((await store.readPatchProgress(db,company)).tickets.find(t=>t.requestId===retainedScope.ticket.id).summary.reappeared,1);
  }finally{
   await db.query("INSERT INTO defender_import_runs VALUES($1,$2,1,'succeeded','2026-10-22T00:00:00.123Z','{}') ON CONFLICT(id) DO UPDATE SET company_id=EXCLUDED.company_id",[run,company]);
   await db.query("INSERT INTO defender_devices VALUES($1,'b',$2) ON CONFLICT DO NOTHING",[run,JSON.stringify({deviceId:'b',lastSeen:'2026-10-21T00:00:00Z'})]);
   await db.query("UPDATE app_findings SET payload=$1 WHERE id='fb'",[JSON.stringify(original)]);await db.query('UPDATE defender_connections SET revision=1');await current(run);
   await db.query('DELETE FROM defender_records WHERE run_id=$1',[newerRun]);await db.query('DELETE FROM defender_devices WHERE run_id=$1',[newerRun]);await db.query('DELETE FROM defender_import_runs WHERE id=$1',[newerRun]);
  }
 });
 await regression('older-created scan completion creates a new history observation',async()=>{
   for(const [id,created,completed] of [['old','2026-10-01','2026-10-23'],['new','2026-10-20','2026-10-24']])await db.query(`INSERT INTO app_scans(id,company_id,connector,status,created_at,payload) VALUES($1,$2,'nessus','Completed',$3,$4)`,[id,company,created,JSON.stringify({id,status:'Completed',completedAt:completed,vendor:{nessusScanId:id==='old'?7:8,imported:true,nessusEvidenceVersion:1}})]);
   const firstClient=await db.connect();let first;try{first=await sources.collectProgressTrends(firstClient,company);}finally{firstClient.release();}await store.saveProgressTrends(db,company,first);
   await db.query(`UPDATE app_scans SET payload=jsonb_set(payload,'{completedAt}','"2026-10-25"') WHERE id='old'`);
   const secondClient=await db.connect();let second;try{second=await sources.collectProgressTrends(secondClient,company);}finally{secondClient.release();}
   assert.ok(second.some(r=>r.source==='total'),'updated older scan must not be skipped');
 });
 await regression('Nessus negative needs the current persisted folder/target/revision scope',async()=>{
   const f={id:'fn',companyId:company,asset:'n',cve,connector:'nessus',status:'Resolved',nessusObservations:{'7':{observedAt:'2026-10-25',present:false}}};
   await db.query('INSERT INTO app_findings(id,company_id,connector,status,cve,asset,payload) VALUES($1,$2,$3,$4,$5,$6,$7)',[f.id,company,'nessus','Resolved',cve,'n',JSON.stringify(f)]);
   const ns=model.progressScope({...ticket,hostCount:1,packet:{appCompanyId:company,source:'stored-findings',connectors:['nessus'],reviewRows:[{asset:'n',cve,findingId:'fn'}]}});
   assert.equal((await sources.collectPatchProgress(db,ns)).rows[0].state,'unknown');
   const {nessusEvidenceScope}=await load('lib/nessus-evidence-scope.ts');
   await db.query(`UPDATE app_scans SET payload=jsonb_set(payload,'{vendor,nessusProgressScope}',$1::jsonb) WHERE id='old'`,[JSON.stringify(nessusEvidenceScope(route))]);
   assert.equal((await sources.collectPatchProgress(db,ns)).rows[0].state,'clear');route.revision++;
   assert.equal((await sources.collectPatchProgress(db,ns)).rows[0].state,'unknown');route.revision--;
   await db.query(`INSERT INTO app_scans(id,company_id,connector,status,created_at,payload) VALUES('new-unpinned',$1,'nessus','Completed','2026-10-26',$2)`,[company,JSON.stringify({id:'new-unpinned',status:'Completed',completedAt:'2026-10-26',vendor:{nessusScanId:7,imported:true,nessusEvidenceVersion:1}})]);
   await db.query(`UPDATE app_findings SET payload=jsonb_set(payload,'{nessusObservations,7,observedAt}','"2026-10-26"') WHERE id='fn'`);
   assert.equal((await sources.collectPatchProgress(db,ns)).rows[0].state,'unknown','an older matching scope cannot validate a newer unpinned import');
 });
 await db.query('INSERT INTO customer_spotlight_routes VALUES($1,\'crowdstrike\',true,$2)',[company,cid]);
 await db.query('INSERT INTO spotlight_import_current VALUES($1,$2)',[company,csRun]);
 await db.query("INSERT INTO spotlight_import_runs VALUES($1,$2,'completed','2026-10-21','2026-10-22',1,1,4)",[csRun,company]);
 await db.query('INSERT INTO spotlight_import_run_scopes VALUES($1,$2,$3,$4)',[csRun,company,cid,binding]);
 const raw={id:'source1',cid,aid:'a',cve:{id:cve},status:'open',updated_timestamp:'2026-10-01',suppression_info:{is_suppressed:false}};
 await db.query('INSERT INTO spotlight_import_records VALUES($1,$2,$2,\'source1\',$3,\'open\',$4)',[csRun,company,cve,JSON.stringify(raw)]);
 await db.query('INSERT INTO spotlight_summary_current VALUES($1,$2,7)',[company,csRun]);
 const summary={deviceCveFindings:1,vendorScope:{version:2,tenantId:cid,mixed:false,missingRows:0,rows:1,localPlaceholderRows:0}};
 await db.query("INSERT INTO spotlight_summary_generations VALUES($1,$2,7,$3,'2026-10-22',1)",[company,csRun,JSON.stringify(summary)]);
 const csScope=model.progressScope({...ticket,packet:{appCompanyId:company,source:'stored-findings',connectors:['crowdstrike'],cves:[cve],hostScope:['a','b'].map(h=>JSON.stringify([cid,h])),deviceCves:['a','b'].map(hostId=>({cid,hostId,cve}))}});
 async function placeholderDisappearance(){
   const withPlaceholder={...summary,vendorScope:{...summary.vendorScope,rows:2,localPlaceholderRows:1}};
   await db.query("INSERT INTO spotlight_import_records VALUES($1,$2,$2,'gone','CS-gone','closed',$3)",[csRun,company,JSON.stringify({id:'gone',unresolved:true})]);
   await db.query('UPDATE spotlight_import_runs SET expected_count=2,hydrated_count=2');
   await db.query('UPDATE spotlight_summary_generations SET summary=$1,source_rows=2',[JSON.stringify(withPlaceholder)]);
   try{
     const result=await sources.collectPatchProgress(db,csScope);
     assert.deepEqual(result.rows.map(r=>r.state),['detected','clear'],'local no-longer-returned placeholders must not block other disappeared CVEs');
     assert.match(result.rows[1].reason,/no longer reported/);
     await db.query(`UPDATE spotlight_import_records SET raw=jsonb_set(raw,'{suppression_info,is_suppressed}','true') WHERE source_id='source1'`);
     assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['unknown','clear'],'suppression must not count as a fix');
     await db.query(`UPDATE spotlight_import_records SET raw=jsonb_set(raw,'{suppression_info,is_suppressed}','false') WHERE source_id='source1'`);
     await db.query("UPDATE spotlight_import_runs SET started_at='2026-10-19'");
     assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['detected','unknown'],'disappearance needs an import started after the ticket');
   }finally{
     await db.query("DELETE FROM spotlight_import_records WHERE source_id='gone'");
     await db.query(`UPDATE spotlight_import_records SET raw=jsonb_set(raw,'{suppression_info,is_suppressed}','false') WHERE source_id='source1'`);
     await db.query("UPDATE spotlight_import_runs SET expected_count=1,hydrated_count=1,started_at='2026-10-21'");
     await db.query('UPDATE spotlight_summary_generations SET summary=$1,source_rows=1',[JSON.stringify(summary)]);
   }
 }
 assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['detected','clear']);
 await regression('uppercase vendor CID and status stay detected instead of becoming falsely fixed',async()=>{
  await db.query(`UPDATE spotlight_import_records SET raw=jsonb_set(raw,'{cid}',$1::jsonb)`,[JSON.stringify(cid.toUpperCase())]);
  assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['detected','clear']);
  await db.query(`UPDATE spotlight_import_records SET raw=jsonb_set(raw,'{status}','"OPEN"')`);
  assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['detected','clear']);
 });
 await regression('existing legacy CrowdStrike import supplies both ticket evidence and customer total',async()=>{
   reviewedSpotlight=false;
   await db.query('DELETE FROM customer_spotlight_routes; DELETE FROM spotlight_import_run_scopes; UPDATE spotlight_import_runs SET checkpoint_version=3');
   assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['detected','clear']);
   const client=await db.connect();let legacy;try{legacy=await sources.collectProgressTrends(client,company);}finally{client.release();}
   assert.equal(legacy.find(t=>t.source==='crowdstrike')?.count,1);
   assert.equal(legacy.find(t=>t.source==='total')?.count,2);
   const different={...csScope,pairs:csScope.pairs.map(p=>({...p,cid:'f'.repeat(32)}))};
   assert.ok((await sources.collectPatchProgress(db,different)).rows.every(r=>r.state==='unknown'));
   await regression('legacy completed import allows disappearance despite local tombstones',placeholderDisappearance);
   reviewedSpotlight=true;
   await db.query('INSERT INTO customer_spotlight_routes VALUES($1,\'crowdstrike\',true,$2)',[company,cid]);
   await db.query('INSERT INTO spotlight_import_run_scopes VALUES($1,$2,$3,$4)',[csRun,company,cid,binding]);
   await db.query('UPDATE spotlight_import_runs SET checkpoint_version=4');
 });
 await regression('reviewed completed import allows disappearance despite local tombstones',placeholderDisappearance);
 await db.query("UPDATE spotlight_import_runs SET expected_count=0,hydrated_count=0");await db.query('DELETE FROM spotlight_import_records');
 assert.deepEqual((await sources.collectPatchProgress(db,csScope)).rows.map(r=>r.state),['clear','clear']);
 await regression('valid zero CrowdStrike generation is recorded as zero customer history',async()=>{
  await db.query("UPDATE app_findings SET status='Resolved'");await db.query('DELETE FROM spotlight_summary_current');
  const client=await db.connect();let empty;try{empty=await sources.collectProgressTrends(client,company);}finally{client.release();}
  assert.equal(empty.find(t=>t.source==='total')?.count,0);
 });
 await db.query("UPDATE spotlight_import_runs SET status='failed'");await assert.rejects(sources.collectPatchProgress(db,csScope));
 console.log('PASS real scoped CrowdStrike comparison, complete-zero import and failed-import refusal');
 assert.deepEqual(regressionFailures,[]);
}finally{await db.end();}
