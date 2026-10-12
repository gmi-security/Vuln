// Synthetic sources; actual CLI and SQL in a fresh private recovery database.
import assert from 'node:assert/strict';import {readFile,writeFile,realpath,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {randomUUID} from 'node:crypto';import pg from 'pg';
import {runRegistry} from '../scripts/customer-connector-registry.mjs';
import {loadConnectorPreview,loadConnectorBindingStore,loadSourceSelection} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
globalThis.fetch=()=>{throw Error('No source or ticket calls permitted');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_source_selection_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
const dir=await mkdtemp(join(tmpdir(),'vuln-source-selection-'));
try{
 await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:2});
 await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb); CREATE TABLE defender_connections(company_id text,tenant_id text,revision int); CREATE TABLE elastic_dashboard_connection(id int,revision int);');
 await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}]]})]);
 await db.query("INSERT INTO defender_connections VALUES('B','private-tenant',1); INSERT INTO elastic_dashboard_connection VALUES(1,1)");
 const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
 const env={DATABASE_URL:url.href,FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:'Alpha'};
 const build=await loadConnectorPreview(),core=await loadSourceSelection(),store=core.createSourceSelectionStore(pool),bindings=(await loadConnectorBindingStore())(pool);
 const collect=async()=>build({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env),run=args=>runRegistry(args,env);
 const command=async(cmd,input)=>{const file=join(dir,randomUUID()+'.json');await writeFile(file,JSON.stringify(input),{mode:0o600});return run([cmd,'--input',file]);};
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 assert.equal((await core.readSourceSelectionStatus(db,'A',await collect())).state,'not-installed');
 await assert.rejects(()=>store.exportCustomer('A',collect),e=>e.code==='42P01');
 await db.query(await readFile('docs/sql/customer-source-selections.sql','utf8'));
 ok('missing schema reports explicit state and never initializes; additive migration seeds no reviews');
 async function bind(company,provider,authority,tenantId,datasets=[]){
  const input=structuredClone((await bindings.list(company,collect)).items.find(i=>i.provider===provider).assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Fixture scope verified',proposal:{companyId:company,tenantId,authority,datasets,targets:[]}});
  await command('assign',input);return input;
 }
 const cs=await bind('A','crowdstrike','findings-primary','a'.repeat(32)),es=await bind('A','elastic','query-only',null,['private-dataset']);
 await bind('B','defender','findings-primary','private-tenant');
 const selection=(await store.exportCustomer('A',collect)).reviewRequest;
 Object.assign(selection,{note:'Fixture mapping verified',mirrors:[{candidateId:es.candidateId,primaryId:cs.candidateId,evidenceRef:'CHANGE-FIXTURE'}]});
 await command('review-sources',selection);
 let exported=await store.exportCustomer('A',collect);assert.equal(exported.status.state,'reviewed');assert.equal(exported.status.primaryCount,1);assert.equal(exported.status.mirrorCount,1);
 const record=(await db.query("SELECT * FROM customer_source_selections WHERE company_id='A'")).rows[0];
 assert.equal((await db.query("SELECT proposal->>'authority' role FROM customer_connector_bindings WHERE candidate_id=$1 AND company_id='A'",[es.candidateId])).rows[0].role,'query-only');
 assert.equal(record.sources.length,2);assert.ok(record.sources.some(s=>s.mirrorOf===cs.candidateId));
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 ok('actual CLI saves primary and mirror evidence plus audit without activating existing bindings');

 const b=(await store.exportCustomer('B',collect)).reviewRequest;b.note='Fixture B review';
 await assert.rejects(()=>command('review-sources',{...b,mirrors:selection.mirrors}),/Mirror target/);
 await command('review-sources',b);assert.equal((await store.exportCustomer('B',collect)).status.primaryCount,1);
 assert.doesNotMatch(JSON.stringify((await store.exportCustomer('B',collect)).bindings),new RegExp(cs.candidateId));
 ok('customer selection and mirror targets cannot refer to another customer');

 await assert.rejects(()=>command('review-sources',selection),/selection changed/);
 const update={...selection,expectedRevision:1};
 const outcomes=await Promise.allSettled([command('review-sources',update),command('review-sources',update)]);
 assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);
 assert.equal((await db.query("SELECT revision FROM customer_source_selections WHERE company_id='A'")).rows[0].revision,2);
 ok('competing operator reviews accept only one expected revision');

 await db.query("CREATE FUNCTION reject_selection_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$");
 await db.query('CREATE TRIGGER reject_selection_audit BEFORE INSERT ON customer_source_selection_audit FOR EACH ROW EXECUTE FUNCTION reject_selection_audit()');
 const revoke={companyId:'A',expectedRevision:2,decision:'revoked',bindingsFingerprint:null,mirrors:[],note:'Fixture revoke'};
 await assert.rejects(()=>command('review-sources',revoke),/fixture audit/);
 assert.equal((await store.exportCustomer('A',collect)).status.state,'reviewed');
 await db.query('DROP TRIGGER reject_selection_audit ON customer_source_selection_audit');
 ok('audit failure rolls back the entire review mutation');

 const file=join(dir,'sources.json');await run(['export-sources','--company','A','--output',file]);
 const out=JSON.parse(await readFile(file,'utf8'));assert.equal(out.reviewRequest.expectedRevision,2);
 assert.doesNotMatch(JSON.stringify(out),/private-dataset|private-tenant|aaaaaaaa|fixture.invalid|CLIENT_SECRET/);
 await assert.rejects(()=>run(['export-sources','--company','A','--output',file]),e=>e.code==='EEXIST');
 ok('private scoped export contains review IDs and evidence references, no source scopes or credentials');

 await db.query('UPDATE elastic_dashboard_connection SET revision=2');
 assert.equal((await store.exportCustomer('A',collect)).status.state,'needs-review');
 await assert.rejects(()=>command('review-sources',{...selection,expectedRevision:2}),/Review all/);
 await command('review-sources',revoke);
 assert.equal((await store.exportCustomer('A',collect)).status.state,'revoked');
 assert.equal((await db.query("SELECT count(*)::int n FROM customer_source_selection_audit WHERE company_id='A'")).rows[0].n,3);
 ok('changed connection revision invalidates review and stale sources remain revocable with audit retained');

 await run(['import','--fingerprint',(await collect()).fingerprint]);
 const before=(await store.exportCustomer('B',collect)).reviewRequest;
 await bind('B','elastic','query-only',null,['other-private-dataset']);
 assert.equal((await store.exportCustomer('B',collect)).status.state,'needs-review');
 await assert.rejects(()=>command('review-sources',{...before,note:'Old binding set'}),/bindings changed/);
 const next=(await store.exportCustomer('B',collect)).reviewRequest;next.note='Reviewed changed source set';await command('review-sources',next);
 assert.equal((await store.exportCustomer('B',collect)).status.state,'reviewed');
 ok('new binding changes complete selection fingerprint; fresh review retains non-endpoint roles separately');
 console.log(`PASS ${checks} isolated source selection groups`);
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
