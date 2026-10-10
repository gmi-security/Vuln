// Disposable fixture database on the private recovery cluster only. Never uses live connector configuration.
import assert from 'node:assert/strict';import {readFile,writeFile,realpath,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {randomUUID} from 'node:crypto';import pg from 'pg';
import {runRegistry} from '../scripts/customer-connector-registry.mjs';
import {loadConnectorPreview,loadConnectorBindingStore,loadAppSecRouting} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata} from '../lib/db/connector-metadata.mjs';
globalThis.fetch=()=>{throw Error('Unexpected source request');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_appsec_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
const dir=await mkdtemp(join(tmpdir(),'vuln-appsec-'));
try{
 await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);await admin.query(`CREATE DATABASE ${name}`);created=true;
 db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:4});
 await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb)');
 await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}]]})]);
 const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
 const env={DATABASE_URL:url.href,APPSEC_ELASTIC_URL:'https://fixture.invalid',APPSEC_ELASTIC_API_KEY:'fixture'},build=await loadConnectorPreview(),routing=(await loadAppSecRouting()).createAppSecRoutingStore(pool,env),bindings=(await loadConnectorBindingStore())(pool);
 const collect=async()=>build({...await readApplicationConnectorMetadata(db),connections:[],tiles:[]},env),run=args=>runRegistry(args,env);
 const command=async(cmd,input)=>{const file=join(dir,randomUUID()+'.json');await writeFile(file,JSON.stringify(input),{mode:0o600});return run([cmd,'--input',file]);};
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 await assert.rejects(()=>routing.read('appsec',collect),e=>e.code==='42P01');
 await db.query(await readFile('docs/sql/customer-appsec-routes.sql','utf8'));assert.deepEqual(await routing.read('appsec',collect),[]);
 ok('additive AppSec migration requires explicit application and seeds no approvals');
 async function bind(company,repos){
  const input=structuredClone((await bindings.list(company,collect)).items.find(i=>i.provider==='appsec').assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Fixture repository ownership',proposal:{companyId:company,tenantId:null,authority:'query-only',targets:repos,datasets:['gmi-appsec-scans','gmi-appsec-findings']}});
  const result=await command('assign',input);return {candidateId:input.candidateId,companyId:company,bindingRevision:result.revision,expectedRevision:0,enabled:true,note:'Fixture AppSec approval'};
 }
 const a=await bind('A',['Acme/Alpha']),b=await bind('B',['Acme/Beta']);await command('route-appsec',a);await command('route-appsec',b);
 let routes=await routing.read('appsec',collect);assert.deepEqual(routes.map(r=>[r.companyId,r.repositories]),[['A',['Acme/Alpha']],['B',['Acme/Beta']]]);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 ok('actual operator CLI approves separate repository ownership without enabling import bindings');
 await assert.rejects(()=>db.query(`UPDATE customer_appsec_routes SET source_scope='["acme/alpha","acme/beta"]' WHERE company_id='B'`),e=>e.code==='23505');
 for(const scope of ['[]','["acme/*"]','["acme/a","acme/a"]','["Acme/Alpha"]','[1]','{}','["acme/.."]','not-json'])
  await assert.rejects(()=>db.query("UPDATE customer_appsec_routes SET source_scope=$1 WHERE company_id='B'",[scope]));
 ok('SQL constraints reject overlaps, wildcard scope, duplicate or malformed repository identities');
 const old=routes[0].bindingKey;
 const updates=await Promise.allSettled([command('route-appsec',{...a,expectedRevision:1}),command('route-appsec',{...a,expectedRevision:1})]);
 assert.equal(updates.filter(r=>r.status==='fulfilled').length,1);assert.notEqual((await routing.read('appsec',collect))[0].bindingKey,old);
 ok('concurrent optimistic revisions accept one update and change the request provenance');
 const conflicting=await bind('B',['ACME/Alpha']);await assert.rejects(()=>command('route-appsec',{...conflicting,expectedRevision:1}),e=>e.code==='23505');
 await assert.rejects(()=>routing.read('appsec',collect),/changed/);
 const repaired=await bind('B',['Acme/Beta']);await command('route-appsec',{...repaired,expectedRevision:1});
 ok('case-insensitive repository ownership blocks cross-customer assignment and stale approvals');
 await db.query("CREATE FUNCTION reject_appsec_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END; $$");
 await db.query('CREATE TRIGGER reject_appsec_audit BEFORE INSERT ON customer_appsec_route_audit FOR EACH ROW EXECUTE FUNCTION reject_appsec_audit()');
 await assert.rejects(()=>command('route-appsec',{...a,expectedRevision:2,enabled:false}),/fixture audit/);
 assert.equal((await db.query("SELECT revision FROM customer_appsec_routes WHERE company_id='A'")).rows[0].revision,2);
 await db.query('DROP TRIGGER reject_appsec_audit ON customer_appsec_route_audit');
 ok('audit write failure rolls back the route mutation');
 const file=join(dir,'routes.json');await run(['export-appsec-routes','--company','A','--output',file]);
 const exported=JSON.parse(await readFile(file,'utf8'));assert.equal(exported.routes.length,1);assert.equal(exported.routes[0].expectedRevision,2);
 assert.doesNotMatch(JSON.stringify(exported),/Acme|acme|fixture.invalid|API_KEY|companyId":"B/);
 await assert.rejects(()=>run(['export-appsec-routes','--company','A','--output',file]),e=>e.code==='EEXIST');
 ok('private customer export omits source scope and refuses an existing destination');
 env.APPSEC_ELASTIC_URL='https://changed.invalid';await assert.rejects(()=>routing.read('appsec',collect),/review/);
 await command('route-appsec',{...a,expectedRevision:2,enabled:false});await command('route-appsec',{...repaired,expectedRevision:2,enabled:false});
 assert.deepEqual(await routing.read('appsec',collect),[]);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_appsec_route_audit')).rows[0].n,6);
 ok('endpoint changes invalidate approval; stale routes remain revocable with audit retained');
 console.log(`PASS ${checks} isolated AppSec routing groups`);
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
