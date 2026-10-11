// Actual persistence, reviewed bindings, worker and SQL reader in ONE disposable
// private database. No application credentials, provider calls or ticket writes.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import pg from 'pg';
import {legacyPersistenceFixture} from './legacy-persistence-fixture.mjs';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {loadConnectorPreview,loadConnectorDraftStore,loadConnectorBindingStore,loadSourceSelection} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
import {readCustomerReportingSections} from '../lib/db/customer-reporting-sections.mjs';
import {createCustomerReportingWorker} from '../lib/db/customer-reporting-worker.mjs';
import {readReportingInputRevision} from '../lib/db/customer-reporting-revisions.mjs';
import {company,reportingFixture,expectedReport} from './reporting-sections-fixture.mjs';
globalThis.fetch=()=>{throw Error('No source calls allowed');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_reporting_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let pool,db,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 pool=new pg.Pool({...config,database:name,max:8});db=await pool.connect();
 for(const file of ['customer-connector-drafts','customer-connector-bindings','customer-source-selections','customer-reporting-sections','customer-reporting-jobs'])
  await db.query(await readFile(`docs/sql/${file}.sql`,'utf8'));
 let fixture=await legacyPersistenceFixture(pool,{VULN_REPORTING_INPUT_REVISIONS:'true'});
 const data=reportingFixture(1200),other={id:'CO-OTHER',name:'Other Customer'};
 for(const f of data.findings){f.connector='defender';delete f.seenBy;delete f.enrichments;}
 for(const s of data.scans)s.connector='defender';for(const a of data.assets)a.source='defender';
 const snapshot={companies:[[company.id,company],[other.id,other]],folders:[],meta:{counter:1},
  findings:[...data.findings,{...data.findings[0],id:'FOREIGN',companyId:other.id}].map(r=>[r.id,r]),
  scans:data.scans.map(r=>[r.id,r]),assets:data.assets.map(r=>[r.id,r])};
 await assert.rejects(()=>fixture.persist.saveSnapshot(snapshot),e=>e.code==='42P01');
 assert.equal((await db.query('SELECT count(*)::int n FROM vuln_store')).rows[0].n,0);
 await db.query(await readFile('docs/sql/customer-reporting-inputs.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-reporting-buckets.sql','utf8'));
 await fixture.persist.saveSnapshot(snapshot);
 for(const row of data.history)await db.query('INSERT INTO vuln_metrics_history(company_id,ts,data) VALUES($1,$2,$3)',[company.id,row.ts,row.data]);
 const revision=async id=>(await db.query('SELECT revision::text,generation,content_hash FROM customer_reporting_inputs WHERE company_id=$1',[id])).rows[0];
 const first=await revision(company.id),foreignFirst=await revision(other.id);
 assert.equal(first.revision,'1');ok('missing explicit migration rolls back actual persistence; installed revisions commit with complete snapshot');

 await db.query('CREATE TABLE defender_connections(company_id text,tenant_id text,revision int)');
 await db.query('INSERT INTO defender_connections VALUES($1,$2,1),($3,$4,1)',[company.id,'private-a',other.id,'private-b']);
 const preview=await loadConnectorPreview(),reviewApi=await loadSourceSelection();
 const collect=async()=>preview({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},{});
 const drafts=(await loadConnectorDraftStore())(pool),bindings=(await loadConnectorBindingStore())(pool),selections=reviewApi.createSourceSelectionStore(pool);
 await drafts.importPreview((await collect()).fingerprint,'test:operator',collect);
 for(const id of [company.id,other.id]){
  const req=structuredClone((await bindings.list(id,collect)).items.find(i=>i.provider==='defender').assignmentRequest);
  Object.assign(req,{decision:'reviewed',note:'Fixture source scope',proposal:{companyId:id,tenantId:id===company.id?'private-a':'private-b',authority:'findings-primary',datasets:[],targets:[]}});
  await bindings.save(req,'test:operator',collect);
  const selection=(await selections.exportCustomer(id,collect)).reviewRequest;selection.note='Fixture primary review';
  await selections.save(selection,'test:operator',collect);
 }
 const {create,reference}=await loadReportingSections(),worker=createCustomerReportingWorker(pool,pool,create,{mode:'published'});
 const review=async()=>reviewApi.readSourceSelectionStatus(db,company.id,await collect());
 const read=async()=>{const s=await pool.connect(),t=await pool.connect();try{return await readCustomerReportingSections(s,t,company.id,{mode:'published',expectedReviewRevision:(await review()).revision});}finally{s.release();t.release();}};
 const refresh=async()=>{const result=await worker.tick([company.id]);assert.equal(result.state,'succeeded');return result;};
 await refresh();let result=await read();assert.equal(result.state,'available');
 // Reference the actual hydrated ordering, exactly as the existing store does.
 const loaded=await fixture.persist.loadSnapshot();
 const expected=expectedReport(reference,{findings:loaded.findings.map(r=>r[1]).filter(r=>r.companyId===company.id),scans:loaded.scans.map(r=>r[1]),assets:loaded.assets.map(r=>r[1]),history:await fixture.persist.loadMetricsHistory(company.id,180)});
 assert.deepEqual(result.model,JSON.parse(JSON.stringify(expected)));const originalReport=result.snapshotId;
 assert.equal((await worker.tick([company.id])).state,'idle');ok('actual reviewed-source worker and saved Overview preserve the complete existing model in the application database');

 snapshot.findings.find(r=>r[0]==='FOREIGN')[1].status='Resolved';snapshot.meta.counter++;
 await fixture.persist.saveSnapshot(snapshot);
 assert.deepEqual(await revision(company.id),first);assert.notEqual((await revision(other.id)).generation,foreignFirst.generation);
 assert.equal((await read()).snapshotId,originalReport);assert.equal((await worker.tick([company.id])).state,'idle');
 snapshot.meta.counter++;await fixture.persist.saveSnapshot(snapshot);assert.deepEqual(await revision(company.id),first);
 ok('another customer and unrelated bookkeeping do not invalidate or rebuild this customer report');

 data.findings[0].status=data.findings[0].status==='Resolved'?'Open':'Resolved';await fixture.persist.saveSnapshot(snapshot);
 assert.notEqual((await revision(company.id)).generation,first.generation);assert.equal((await read()).state,'stale');await refresh();
 for(const change of [()=>data.scans[0].status='Failed',()=>data.assets[0].identifier='changed-device']){
  change();await fixture.persist.saveSnapshot(snapshot);assert.equal((await read()).state,'stale');await refresh();
 }
 await db.query('INSERT INTO vuln_metrics_history(company_id,data) VALUES($1,$2)',[company.id,{totalOpen:27}]);
 assert.equal((await read()).state,'stale');await refresh();ok('workflow, scan, asset and recorded-history changes each invalidate only the affected customer output');

 const before=await revision(company.id),count=(await db.query('SELECT model->\'metrics\' metrics FROM customer_reporting_sections WHERE company_id=$1',[company.id])).rows[0];
 fixture.onWrite(async()=>{throw Error('Injected source publication failure');});data.findings[1].status='Resolved';
 await assert.rejects(()=>fixture.persist.saveSnapshot(snapshot),/Injected/);assert.deepEqual(await revision(company.id),before);
 assert.equal((await read()).state,'available');fixture.onWrite(null);await fixture.persist.saveSnapshot(snapshot);await refresh();
 assert.ok(count);ok('a failed source write keeps prior data and prior report current together; retry publishes the pending workflow change');

 await db.query("UPDATE vuln_store SET updated_at=clock_timestamp() WHERE key='findings:00'");
 await assert.rejects(read,/publication is missing|no longer matches/);
 await assert.rejects(()=>fixture.persist.saveSnapshot(snapshot),/outside this writer/);
 await fixture.persist.loadSnapshot();await fixture.persist.saveSnapshot(snapshot);assert.equal((await read()).state,'available');
 ok('untracked older-writer changes withhold the report and cannot be silently recertified from a stale process');

 const input=(await selections.exportCustomer(company.id,collect)).reviewRequest;input.note='Repeat current review';
 await selections.save(input,'test:operator',collect);assert.equal((await read()).state,'stale');await refresh();
 await db.query("UPDATE customer_source_selections SET state='revoked',bindings_fingerprint=NULL,mirrors='[]',revision=revision+1 WHERE company_id=$1",[company.id]);
 await assert.rejects(read,/source review/);assert.equal((await worker.tick([company.id])).unavailable,1);
 const next=(await selections.exportCustomer(company.id,collect)).reviewRequest;next.note='Restore fixture review';await selections.save(next,'test:operator',collect);await refresh();
 ok('changed/revoked source review fences reports and jobs until a current review is restored');

 const savedId=(await read()).snapshotId;data.findings[2].connector='crowdstrike';await fixture.persist.saveSnapshot(snapshot);
 const rejected=await worker.tick([company.id]);assert.equal(rejected.state,'retry-or-superseded');assert.equal((await read()).state,'stale');
 assert.equal((await db.query('SELECT snapshot_id FROM customer_reporting_sections WHERE company_id=$1',[company.id])).rows[0].snapshot_id,savedId);
 data.findings[2].connector='defender';await fixture.persist.saveSnapshot(snapshot);await refresh();
 const beforeInventory=(await read()).snapshotId;data.assets[0].source='tidal';await fixture.persist.saveSnapshot(snapshot);
 assert.equal((await worker.tick([company.id])).state,'retry-or-superseded');assert.equal((await read()).state,'stale');
 assert.equal((await db.query('SELECT snapshot_id FROM customer_reporting_sections WHERE company_id=$1',[company.id])).rows[0].snapshot_id,beforeInventory);
 data.assets[0].source='defender';await fixture.persist.saveSnapshot(snapshot);await refresh();
 ok('unassigned finding and inventory providers reject the entire refresh without dropping records or replacing the prior report');

 const mapped=await readReportingInputRevision(db,other.id);assert.equal(mapped.buckets.length,2);
 assert.equal((await worker.tick([other.id])).bucketsRead,1);
 snapshot.findings=snapshot.findings.filter(r=>r[0]!=='FOREIGN');await fixture.persist.saveSnapshot(snapshot);
 const empty=await worker.tick([other.id]);assert.equal(empty.records,0);assert.equal(empty.bucketsRead,0);
 snapshot.findings.push(['FOREIGN-NEW',{...data.findings[0],id:'FOREIGN-NEW',companyId:other.id}]);
 await fixture.persist.saveSnapshot(snapshot);assert.equal((await worker.tick([other.id])).records,1);
 snapshot.findings.at(-1)[1].companyId=company.id;await fixture.persist.saveSnapshot(snapshot);
 assert.equal((await worker.tick([other.id])).bucketsRead,0);
 ok('small and empty customers scan only their mapped buckets; added, removed and reassigned records update the map atomically');

 const goodMap=(await db.query('SELECT bucket_map FROM customer_reporting_inputs WHERE company_id=$1',[company.id])).rows[0].bucket_map;
 await db.query('UPDATE customer_reporting_inputs SET bucket_map=$2 WHERE company_id=$1',[company.id,JSON.stringify(goodMap.filter(p=>p[0]==='companies:00'))]);
 await assert.rejects(()=>readReportingInputRevision(db,company.id),/Invalid customer reporting bucket map/);
 await fixture.persist.saveSnapshot(snapshot);assert.deepEqual((await readReportingInputRevision(db,company.id)).buckets,goodMap.map(p=>p[0]));
 await db.query('UPDATE customer_reporting_inputs SET format_version=1,bucket_map=NULL');
 await db.query('UPDATE customer_reporting_publication SET format_version=1');
 await assert.rejects(()=>readReportingInputRevision(db,other.id),/publication is missing/);
 await fixture.persist.saveSnapshot(snapshot);assert.deepEqual((await readReportingInputRevision(db,other.id)).buckets,['companies:00']);
 ok('incomplete maps and legacy input versions are withheld until the real writer republishes a complete current map');

 const u=new URL(`postgresql://codex@localhost/${name}`);u.searchParams.set('host',socket);u.searchParams.set('port','55483');
 const child=await promisify(execFile)(process.execPath,['--max-old-space-size=512','scripts/customer-reporting-worker.mjs','--once'],{timeout:30000,env:{PATH:process.env.PATH,
  VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:other.id,VULN_REPORTING_STORAGE:'published',VULN_REPORTING_INPUT_REVISIONS:'true',
  DATABASE_URL:u.href,VULN_REPORTING_SOURCE_URL:u.href,VULN_REPORTING_DATABASE_URL:u.href}});
 assert.match(child.stdout,/"state":"succeeded"/);assert.doesNotMatch(child.stdout,/private-a|private-b|postgresql/);
 ok('actual compiled worker CLI supports the explicit single application database mode with sanitized output');
 console.log(JSON.stringify({checks,database:'disposable-private',sourceCalls:0}));
}finally{db?.release();await pool?.end();if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();}
