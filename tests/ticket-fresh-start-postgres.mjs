// Only a newly created fixture database on the private Unix-socket test cluster.
import assert from 'node:assert/strict';
import {realpath,readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import pg from 'pg';
import {inspectTicketFreshStart,applyTicketFreshStart,ticketTables,ticketHistorySchema} from '../lib/db/ticket-fresh-start.mjs';
const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000};
const name='vuln2_ticket_reset_test_'+randomUUID().replaceAll('-','');
const reader='ticket_reset_reader_'+randomUUID().replaceAll('-','');let readerCreated=false;
const admin=new pg.Client({...config,database:'postgres'});let db,other,pool,created=false,checks=0;
const pass=message=>{checks++;console.log('PASS '+message);};
try{
 await admin.connect();const g=(await admin.query("SELECT current_setting('data_directory') dir,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(g.dir.startsWith('/home/codex/vuln-recovery/')&&!g.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;db=new pg.Client({...config,database:name});await db.connect();
 // Exercise the actual production ticket DDL, without loading the app or providers.
 const source=await readFile(new URL('../lib/patch-ticket-store.ts',import.meta.url),'utf8');
 const ddl=source.match(/ready \?\?= db\.query\(`([\s\S]*?)`\)\.then/);assert.ok(ddl);await db.query(ddl[1]);
 await db.query(`CREATE TABLE defender_connections(company_id text PRIMARY KEY,secret text);
  INSERT INTO defender_connections VALUES('fixture-customer','fixture-secret');
  CREATE TABLE customer_connector_bindings(company_id text,provider text);
  INSERT INTO customer_connector_bindings VALUES('fixture-customer','defender');
  CREATE TABLE elastic_dashboard_queries(id text,definition jsonb);
  INSERT INTO elastic_dashboard_queries VALUES('tile','{"companyId":"fixture-customer"}');
  INSERT INTO patch_connectwise_connection(id,secret,target) VALUES(1,'fixture-ciphertext','fixture-target');
  INSERT INTO patch_customer_routing VALUES('fixture-customer',42,9,NULL,now(),'fixture');`);
 const oldSingle=randomUUID(),oldGroup=randomUUID();
 await db.query(`INSERT INTO patch_ticket_requests(id,cve,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,tenant_ids,scope_hash,state)
  VALUES($1,'CVE-2026-1234','fixture',now(),1,'{}',1,'[]','single','failed')`,[oldSingle]);
 await db.query(`INSERT INTO patch_group_ticket_requests(id,cves,remediation_id,tenant_id,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,finding_count,scope_hash,state,review_state)
  VALUES($1,'[]','fix','tenant','fixture',now(),1,'{}',1,1,'group','prepared','approved')`,[oldGroup]);
 await db.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,'fixture','created')",[oldSingle]);
 await db.query("INSERT INTO patch_group_ticket_audit(request_id,actor,action) VALUES($1,'fixture','prepared')",[oldGroup]);
 await db.query(`CREATE ROLE ${reader}`);readerCreated=true;
 await db.query(`GRANT SELECT,INSERT ON patch_ticket_audit TO ${reader}; GRANT USAGE ON SEQUENCE patch_ticket_audit_id_seq TO ${reader}`);
 await db.query('REVOKE TRUNCATE ON patch_ticket_audit FROM CURRENT_USER');
 const before=await inspectTicketFreshStart(db);
 assert.equal(before.tables.length,4);assert.ok(/^[a-f0-9]{64}$/.test(before.planHash));
 pass('read-only plan identifies exact ticket tables and protected configuration');
 await assert.rejects(applyTicketFreshStart(db,{writersStopped:true,expectedPlanHash:'0'.repeat(64)}),/plan changed/);
 assert.equal((await db.query('SELECT count(*)::int n FROM patch_ticket_requests')).rows[0].n,1);
 pass('changed plan is refused without moving or losing records');
 other=new pg.Client({...config,database:name});await other.connect();
 await assert.rejects(applyTicketFreshStart(db,{writersStopped:true,expectedPlanHash:before.planHash}),/other database sessions/);
 await other.end();other=null;pass('another database session prevents retirement');
 await db.query('CREATE VIEW test_ticket_dependency AS SELECT id FROM patch_ticket_requests');
 await assert.rejects(inspectTicketFreshStart(db),/dependencies/);
 await db.query('DROP VIEW test_ticket_dependency');
 await db.query('CREATE TABLE test_ticket_fk(request_id uuid REFERENCES patch_ticket_requests(id))');
 await assert.rejects(inspectTicketFreshStart(db),/foreign keys/);
  await db.query('DROP TABLE test_ticket_fk');pass('unexpected views and foreign keys require review');
 await db.query(`GRANT SELECT(actor) ON patch_ticket_audit TO ${reader}`);
 await assert.rejects(inspectTicketFreshStart(db),/column permissions/);
 await db.query(`REVOKE SELECT(actor) ON patch_ticket_audit FROM ${reader}`);
 await db.query('ALTER TABLE patch_ticket_audit ADD COLUMN unsupported_identity bigint GENERATED ALWAYS AS IDENTITY');
 await assert.rejects(inspectTicketFreshStart(db),/Identity ticket sequences/);
 await db.query('ALTER TABLE patch_ticket_audit DROP COLUMN unsupported_identity');
 await db.query('ALTER SEQUENCE patch_ticket_audit_id_seq INCREMENT BY 2');
 await assert.rejects(inspectTicketFreshStart(db),/Nonstandard ticket sequence/);
 await db.query('ALTER SEQUENCE patch_ticket_audit_id_seq INCREMENT BY 1');
 pass('column grants, identity columns and customized sequence parameters fail closed before mutation');
 // A real SQL error after the first ALTER TABLE must roll the whole transaction back.
 let intercepted=false;
 const fault={async query(sql,params){if(!intercepted&&sql.startsWith('CREATE TABLE public.')){intercepted=true;return db.query('SELECT 1/0');}return db.query(sql,params);}};
 await assert.rejects(applyTicketFreshStart(fault,{writersStopped:true,expectedPlanHash:before.planHash}),/division by zero/);
 assert.deepEqual(await inspectTicketFreshStart(db),before);pass('partial DDL failure rolls back tables, sequences and metadata');
 const result=await applyTicketFreshStart(db,{writersStopped:true,expectedPlanHash:before.planHash});
 assert.equal(result.configurationPreserved,true);
 for(const table of ticketTables){
  assert.equal((await db.query(`SELECT count(*)::int n FROM public.${table}`)).rows[0].n,0);
  assert.equal((await db.query(`SELECT count(*)::int n FROM ${ticketHistorySchema}.${table}`)).rows[0].n,1);
  assert.equal((await db.query('SELECT $1::regclass::oid::text oid',[ticketHistorySchema+'.'+table])).rows[0].oid,before.tables.find(t=>t.name===table).oid);
 }
 assert.equal((await db.query('SELECT id FROM patch_ticket_requests WHERE id=$1',[oldSingle])).rowCount,0);
 assert.equal((await db.query('SELECT id FROM patch_group_ticket_requests WHERE id=$1',[oldGroup])).rowCount,0);
 pass('old requests and audit rows remain in place historically and are absent from active lookup/queue tables');
 // Re-running the application initializer must not collide with archived indexes or sequences.
 await db.query(ddl[1]);
 const fresh=randomUUID();await db.query(`INSERT INTO patch_ticket_requests(id,cve,prepared_by,prepared_at,crowdstrike_revision,packet,host_count,tenant_ids,scope_hash)
  VALUES($1,'CVE-2026-1234','fixture',now(),1,'{}',1,'[]','single')`,[fresh]);
 const audit=(await db.query("INSERT INTO patch_ticket_audit(request_id,actor,action) VALUES($1,'fixture','new') RETURNING id",[fresh])).rows[0];assert.equal(audit.id,'1');
 assert.equal((await db.query(`SELECT last_value::text FROM ${ticketHistorySchema}.patch_ticket_audit_id_seq`)).rows[0].last_value,'1');
 assert.equal((await db.query("SELECT has_table_privilege($1,'public.patch_ticket_audit','INSERT') allowed",[reader])).rows[0].allowed,true);
 assert.equal((await db.query("SELECT has_sequence_privilege($1,'public.patch_ticket_audit_id_seq','USAGE') allowed",[reader])).rows[0].allowed,true);
 const ownerTruncate=(await db.query(`SELECT x.privilege_type FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x
  WHERE c.oid='public.patch_ticket_audit'::regclass AND x.grantee=c.relowner AND x.privilege_type='TRUNCATE'`)).rowCount;
 assert.equal(ownerTruncate,0,'Explicitly revoked owner privileges must stay revoked');
 assert.equal((await db.query("SELECT count(*)::int n FROM pg_indexes WHERE schemaname='public' AND tablename=ANY($1::text[])",[ticketTables])).rows[0].n,8);
 pass('fresh application inserts use independent sequences and retain primary/unique/index constraints');
 assert.equal((await db.query('SELECT secret FROM defender_connections')).rows[0].secret,'fixture-secret');
 assert.equal((await db.query('SELECT company_id FROM customer_connector_bindings')).rows[0].company_id,'fixture-customer');
 assert.equal((await db.query('SELECT secret FROM patch_connectwise_connection')).rows[0].secret,'fixture-ciphertext');
 assert.equal((await db.query('SELECT app_company_id FROM patch_customer_routing')).rows[0].app_company_id,'fixture-customer');
 assert.equal((await db.query('SELECT definition FROM elastic_dashboard_queries')).rows[0].definition.companyId,'fixture-customer');
 pass('customer bindings, encrypted credentials, routing and saved tiles survive unchanged');
 // Invoke the real ticket stores after reset; every external operation is a
 // forbidden dependency, not a simulated successful ConnectWise response.
 pool=new pg.Pool({...config,database:name,max:1});pool.on('error',()=>{});
 let providerCalls=0;const forbidden=async()=>{providerCalls++;throw Error('Provider call forbidden');};
 const mocks={
  './elastic-dashboard-store':{dashboardDatabase:async()=>pool,assertPatchRequestScope:async()=>{},verifyAgainstCrowdStrike:forbidden},
  './reporting-tenant-scope':{customerFalconTenantIds:()=>[]},
  './reporting-direct-sources':{atlasFalconReviewPacket:forbidden},
  './customer-consolidation-hold':{requiresConsolidationManualReview:()=>false},
  './patch-request':{parsePatchInput:()=>{throw Error('Packet preparation is outside this retirement test');}},
 };
 const modules=new Map();const synthetic=values=>new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});
 async function getModule(path){path=resolve(path);if(!modules.has(path))modules.set(path,(async()=>new SourceTextModule(ts.transpileModule(await readFile(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path}))());return modules.get(path);}
 async function linker(spec,parent){if(mocks[spec])return synthetic(mocks[spec]);if(spec.startsWith('.'))return getModule(resolve(dirname(parent.identifier),spec+(/\.(ts|mjs|js)$/.test(spec)?'':'.ts')));if(spec.startsWith('@/'))return getModule(resolve(spec.slice(2)+(/\.(ts|mjs|js)$/.test(spec)?'':'.ts')));return synthetic(await import(spec));}
 async function load(path){const m=await getModule(path);if(m.status==='unlinked')await m.link(linker);await m.evaluate();return m.namespace;}
 const cw=await load('lib/connectwise-client.ts');
 mocks['./connectwise-client']={...cw,openCWConnection:()=>({endpoint:'https://api-na.myconnectwise.net/v4_6_release/apis/3.0',companyId:'fixture',clientId:'fixture',publicKey:'fixture',privateKey:'fixture'}),
  cwRequest:forbidden,findCWRequest:forbidden,uploadPatchCsv:forbidden,validateCWRouting:forbidden};
 const single=await load('lib/patch-ticket-store.ts'),group=await load('lib/patch-group-ticket-store.ts');
 const input={title:'Patch fixture',body:'Fixture request',routing:{companyId:42,boardId:9}};
 for(const [store,id,read,create,action] of [[single,oldSingle,'readPatchTicket','createPatchTicket','patchTicketAction'],[group,oldGroup,'readGroupTicket','createGroupTicket','groupTicketAction']]){
  await assert.rejects(store[read](id),/not found/i);
  await assert.rejects(store[create](id,input,'fixture'),/not found/i);
  for(const operation of ['reconcile','retry-attachment','check-status'])await assert.rejects(store[action](id,operation,'fixture'),/not found/i);
 }
 await assert.rejects(group.reviewGroupTicket(oldGroup,'reopen','fixture'),/not found/i);
 assert.equal(providerCalls,0);await pool.end();pool=null;
 pass('actual single/group ticket stores reject archived IDs, reopening, reconciliation and attachment retries before provider calls');
 await assert.rejects(applyTicketFreshStart(db,{writersStopped:true,expectedPlanHash:before.planHash}),/already exists/);
 assert.equal((await db.query('SELECT id FROM public.patch_ticket_requests')).rows[0].id,fresh);
 pass('repeat application refuses and cannot retire new tickets');
 console.log(JSON.stringify({checks,passed:true,productionWrites:0,providerCalls:0}));
}finally{await pool?.end();await other?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH(FORCE)`);if(readerCreated)await admin.query(`DROP ROLE ${reader}`);await admin.end();}
