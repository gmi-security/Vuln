// Disposable fixture database on the private recovery cluster only. Never uses live connector configuration.
import assert from 'node:assert/strict';import {readFile,writeFile,realpath,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {randomUUID} from 'node:crypto';import pg from 'pg';
import {runRegistry} from '../scripts/customer-connector-registry.mjs';
import {loadConnectorPreview,loadConnectorBindingStore,loadQueryRouting} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata,readDashboardConnectorMetadata} from '../lib/db/connector-metadata.mjs';
globalThis.fetch=()=>{throw Error('Unexpected source request');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_query_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
const dir=await mkdtemp(join(tmpdir(),'vuln-query-'));
try{
 await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:4});
 await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb)');
 await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}]]})]);
 await db.query("CREATE TABLE dashboard_source_connections(source text PRIMARY KEY, revision integer); INSERT INTO dashboard_source_connections VALUES('crowdstrike',1)");
 const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
 const env={DATABASE_URL:url.href},build=await loadConnectorPreview(),routing=(await loadQueryRouting()).createQueryRoutingStore(pool),bindings=(await loadConnectorBindingStore())(pool);
 const collect=async()=>build({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env),run=args=>runRegistry(args,env);
 const command=async(cmd,input)=>{const file=join(dir,randomUUID()+'.json');await writeFile(file,JSON.stringify(input),{mode:0o600});return run([cmd,'--input',file]);};
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 await assert.rejects(()=>routing.read('crowdstrike',collect),e=>e.code==='42P01');
 await db.query(await readFile('docs/sql/customer-inventory-routes.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-inventory-routes-v2.sql','utf8'));
 await db.query('CREATE TABLE spotlight_import_runs(id UUID PRIMARY KEY)');
 await db.query(await readFile('docs/sql/customer-spotlight-routes.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-query-routes.sql','utf8'));assert.deepEqual(await routing.read('crowdstrike',collect),[]);
 ok('query approval requires an explicit additive migration and starts empty');
 async function bind(company,cid){
  const input=structuredClone((await bindings.list(company,collect)).items.find(i=>i.provider==='crowdstrike').assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Fixture verified CID',proposal:{companyId:company,tenantId:cid,authority:'query-only',targets:[],datasets:[]}});
  const result=await command('assign',input);return {candidateId:input.candidateId,companyId:company,bindingRevision:result.revision,expectedRevision:0,enabled:true,note:'Fixture query approval'};
 }
 const a=await bind('A','a'.repeat(32)),b=await bind('B','b'.repeat(32));await command('route-query',a);await command('route-query',b);
 let routes=await routing.read('crowdstrike',collect);assert.deepEqual(routes.map(r=>[r.companyId,r.sourceScope,r.connectionRevision]),[['A','a'.repeat(32),1],['B','b'.repeat(32),1]]);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 ok('actual CLI approves separate CID ownership on one saved connection without activating import bindings');
 for(const table of ['customer_inventory_routes','customer_spotlight_routes']){
  const insert=`INSERT INTO ${table}(candidate_id,company_id,provider,source_scope,binding_revision,candidate_hash,revision,enabled) SELECT candidate_id,'B',provider,source_scope,binding_revision,candidate_hash,1,true FROM customer_query_routes WHERE company_id='A'`;
  await assert.rejects(()=>db.query(insert),e=>e.code==='23505');
  await db.query("UPDATE customer_query_routes SET enabled=false WHERE company_id='A'");
  await db.query(insert);
  await assert.rejects(()=>db.query("UPDATE customer_query_routes SET enabled=true WHERE company_id='A'"),e=>e.code==='23505');
  await db.query(`DELETE FROM ${table}`);await db.query("UPDATE customer_query_routes SET enabled=true WHERE company_id='A'");
 }
 ok('query, inventory and Spotlight approvals cannot assign the same CID to different customers in either direction');
 const old=routes[0].bindingKey;
 const updates=await Promise.allSettled([command('route-query',{...a,expectedRevision:1}),command('route-query',{...a,expectedRevision:1})]);
 assert.equal(updates.filter(r=>r.status==='fulfilled').length,1);assert.equal(updates.filter(r=>r.status==='rejected').length,1);
 assert.notEqual((await routing.read('crowdstrike',collect))[0].bindingKey,old);
 ok('concurrent expected revisions accept one update and change the result provenance key');
 const dupe=await bind('B','a'.repeat(32));await assert.rejects(()=>command('route-query',{...dupe,expectedRevision:1}),e=>e.code==='23505');
 await assert.rejects(()=>routing.read('crowdstrike',collect),/changed/);
 const repaired=await bind('B','b'.repeat(32));await command('route-query',{...repaired,expectedRevision:1});
 ok('duplicate CID ownership is rejected; changed assignments invalidate previous routing');
 await db.query("CREATE FUNCTION reject_query_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$");
 await db.query('CREATE TRIGGER reject_query_audit BEFORE INSERT ON customer_query_route_audit FOR EACH ROW EXECUTE FUNCTION reject_query_audit()');
 await assert.rejects(()=>command('route-query',{...a,expectedRevision:2,enabled:false}),/fixture audit/);
 assert.equal((await db.query("SELECT revision FROM customer_query_routes WHERE company_id='A'")).rows[0].revision,2);
 await db.query('DROP TRIGGER reject_query_audit ON customer_query_route_audit');
 ok('audit failure rolls back the route update');
 const file=join(dir,'routes.json');await run(['export-query-routes','--company','A','--output',file]);
 const exported=JSON.parse(await readFile(file,'utf8'));assert.equal(exported.routes.length,1);assert.equal(exported.routes[0].expectedRevision,2);
 assert.doesNotMatch(JSON.stringify(exported),new RegExp('a'.repeat(32)+'|secret|companyId":"B'));
 await assert.rejects(()=>run(['export-query-routes','--company','A','--output',file]),e=>e.code==='EEXIST');
 ok('scoped exports omit CIDs and credentials and never overwrite a prior file');
 await db.query("UPDATE dashboard_source_connections SET revision=2");await assert.rejects(()=>routing.read('crowdstrike',collect),/review/);
 await command('route-query',{...a,expectedRevision:2,enabled:false});await command('route-query',{...repaired,expectedRevision:2,enabled:false});
 assert.deepEqual(await routing.read('crowdstrike',collect),[]);
 ok('credential revision changes fail closed and stale approvals remain revocable');
 // Elastic v2 upgrades in place and allows one approval per provider/customer.
 await db.query("UPDATE dashboard_source_connections SET revision=1");
 await command('route-query',{...a,expectedRevision:3});
 const csBefore=await routing.read('crowdstrike',collect);
 await db.query(await readFile('docs/sql/customer-query-routes-v2.sql','utf8'));
 assert.deepEqual(await routing.read('crowdstrike',collect),csBefore);
 assert.deepEqual(await routing.read('elastic',collect),[]);
 await db.query('CREATE TABLE elastic_dashboard_connection(id integer PRIMARY KEY,revision integer); INSERT INTO elastic_dashboard_connection VALUES(1,1)');
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 async function elasticBind(company,datasets){
  const input=structuredClone((await bindings.list(company,collect)).items.find(i=>i.provider==='elastic').assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Fixture exclusive dataset ownership',proposal:{companyId:company,tenantId:null,authority:'query-only',targets:[],datasets}});
  const result=await command('assign',input);return {candidateId:input.candidateId,companyId:company,bindingRevision:result.revision,expectedRevision:0,enabled:true,note:'Fixture Elastic query approval'};
 }
 const ea=await elasticBind('A',['logs-alpha','assets-alpha']),eb=await elasticBind('B',['logs-beta']);
 await command('route-query',ea);await command('route-query',eb);
 assert.deepEqual((await routing.read('elastic',collect)).map(r=>[r.companyId,JSON.parse(r.sourceScope)]),[['A',['assets-alpha','logs-alpha']],['B',['logs-beta']]]);
 assert.deepEqual(await routing.read('crowdstrike',collect),csBefore);
 ok('v2 preserves CrowdStrike proof and audit while allowing separate Elastic approvals per customer');
 await assert.rejects(()=>db.query(`UPDATE customer_query_routes SET source_scope='["logs-alpha","extra"]' WHERE provider='elastic' AND company_id='B'`),e=>e.code==='23505');
 for(const scope of ['[]','["logs-*"]','["a","a"]','[1]','{}','[".ds-stream-000001"]','not-json'])
  await assert.rejects(()=>db.query("UPDATE customer_query_routes SET source_scope=$1 WHERE provider='elastic' AND company_id='B'",[scope]));
 ok('database constraints reject overlapping subsets, wildcard scopes, duplicates and malformed dataset values');
 const conflicting=await elasticBind('B',['logs-alpha','logs-beta']);
 await assert.rejects(()=>command('route-query',{...conflicting,expectedRevision:1}),e=>e.code==='23505');
 await assert.rejects(()=>routing.read('elastic',collect),/changed/);
 const repairedElastic=await elasticBind('B',['logs-beta']);await command('route-query',{...repairedElastic,expectedRevision:1});
 const elasticProof=(await routing.read('elastic',collect))[0].bindingKey;
 const race=await Promise.allSettled([command('route-query',{...ea,expectedRevision:1}),command('route-query',{...ea,expectedRevision:1})]);
 assert.equal(race.filter(r=>r.status==='fulfilled').length,1);assert.notEqual((await routing.read('elastic',collect))[0].bindingKey,elasticProof);
 ok('actual CLI rejects cross-customer dataset ownership and preserves revision fencing');
 const exportBoth=join(dir,'both-routes.json');await run(['export-query-routes','--company','A','--output',exportBoth]);
 const both=JSON.parse(await readFile(exportBoth,'utf8'));assert.equal(both.routes.length,2);assert.doesNotMatch(JSON.stringify(both),/logs-alpha|assets-alpha/);
 await db.query('UPDATE elastic_dashboard_connection SET revision=2');await assert.rejects(()=>routing.read('elastic',collect),/review/);
 assert.deepEqual(await routing.read('crowdstrike',collect),csBefore);
 await command('route-query',{...ea,expectedRevision:2,enabled:false});await command('route-query',{...repairedElastic,expectedRevision:2,enabled:false});
 assert.deepEqual(await routing.read('elastic',collect),[]);
 ok('exports hide dataset names; Elastic credential changes withhold only Elastic; stale approvals remain revocable');
 console.log(`PASS ${checks} isolated query routing groups`);
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
