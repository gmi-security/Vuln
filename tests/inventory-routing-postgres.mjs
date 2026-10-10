// Disposable database on the private recovery cluster only. No vendor calls.
import assert from 'node:assert/strict';
import {readFile,writeFile,realpath,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {runRegistry} from '../scripts/customer-connector-registry.mjs';
import {loadConnectorPreview,loadConnectorBindingStore,loadInventoryRouting} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata} from '../lib/db/connector-metadata.mjs';
globalThis.fetch=()=>{throw Error('Unexpected vendor operation');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_inventory_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
const dir=await mkdtemp(join(tmpdir(),'vuln-inventory-'));
try{
 await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;
 db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:4});
 await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb)');
 const companies=[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}],['DEMO',{id:'DEMO',name:'Demo',isDemo:true}]];
 await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies})]);
 const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
 const tenant='11111111-1111-1111-1111-111111111111';
 const env={DATABASE_URL:url.href,AUTOMATE_BASE_URL:'https://not-contacted.invalid',AUTOMATE_API_CLIENT_ID:'fixture',AUTOMATE_USERNAME:'fixture',AUTOMATE_PASSWORD:'fixture',
  INTUNE_TENANT_ID:tenant,INTUNE_CLIENT_ID:'fixture',INTUNE_CLIENT_SECRET:'fixture',SPIDERFOOT_URL:'https://not-contacted.invalid',
  TIDAL_EMAIL:'fixture',TIDAL_PASSWORD:'fixture',FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',
  FALCON_CLIENT_ID_2:'fixture2',FALCON_CLIENT_SECRET_2:'fixture',FALCON_CUSTOMER_2:'Beta'};
 const build=await loadConnectorPreview(),core=await loadInventoryRouting(),routing=core.createInventoryRoutingStore(pool),bindings=(await loadConnectorBindingStore())(pool);
 const collect=async()=>build({...await readApplicationConnectorMetadata(db),connections:[],tiles:[]},env);
 const run=args=>runRegistry(args,env);
 const command=async(name,input)=>{const path=join(dir,randomUUID()+'.json');await writeFile(path,JSON.stringify(input),{mode:0o600});return run([name,'--input',path]);};
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 await assert.rejects(()=>routing.read('automate',collect),e=>e.code==='42P01');
 assert.equal((await db.query("SELECT to_regclass('customer_inventory_routes') n")).rows[0].n,null);
 await db.query(await readFile('docs/sql/customer-inventory-routes.sql','utf8'));
 assert.deepEqual(await routing.read('automate',collect),[]);
 ok('missing routing schema fails without creating it; explicit migration starts with no operational approvals');

 async function bind(company,provider,scope,ref){
  const list=await bindings.list(company,collect),input=structuredClone(list.items.find(i=>i.provider===provider&&(!ref||i.connectionRef===ref)).assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Synthetic reviewed customer scope'});
  input.proposal={companyId:company,tenantId:scope,datasets:[],targets:provider==='spiderfoot'?['fixture.example']:[],authority:provider==='spiderfoot'?'findings-primary':'inventory'};
  const result=await command('assign',input);assert.equal(result.enabledBindings,0);
  return {candidateId:input.candidateId,companyId:company,bindingRevision:result.revision,expectedRevision:0,enabled:true,note:'Synthetic operational approval'};
 }
 const a=await bind('A','automate','17'),b=await bind('B','automate','18'),i=await bind('A','intune',tenant);
 assert.deepEqual(await routing.read('automate',collect),[]);
 assert.equal((await command('route-inventory',a)).revision,1);
 await command('route-inventory',b);await command('route-inventory',i);
 const routes=await routing.read('automate',collect);
 assert.deepEqual(routes.map(r=>[r.companyId,r.sourceScope]),[['A','17'],['B','18']]);
 assert.equal((await routing.read('intune',collect))[0].companyId,'A');
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_inventory_route_audit')).rows[0].n,3);
 ok('actual CLI reviews stay inactive until separate audited inventory approvals; exact client and tenant routes are then readable');

 const ta=await bind('A','tidal','Vendor-A'),tb=await bind('B','tidal','Vendor-B');
 await assert.rejects(()=>command('route-inventory',ta),e=>e.code==='23514');
 await db.query(await readFile('docs/sql/customer-inventory-routes-v2.sql','utf8'));
 await command('route-inventory',ta);await command('route-inventory',tb);
 assert.deepEqual((await routing.read('tidal',collect)).map(r=>[r.companyId,r.sourceScope]),[['A','Vendor-A'],['B','Vendor-B']]);
 assert.equal((await routing.read('automate',collect)).length,2);assert.equal((await routing.read('intune',collect)).length,1);
 const badTidal=await bind('B','tidal','Vendor-A');badTidal.expectedRevision=1;
 await assert.rejects(()=>command('route-inventory',badTidal),e=>e.code==='23505');
 const repairedTidal=await bind('B','tidal','Vendor-B');repairedTidal.expectedRevision=1;await command('route-inventory',repairedTidal);
 ok('explicit v2 migration preserves old approvals, supports case-sensitive Tidal company IDs and rejects duplicate active ownership');

 const ca=await bind('A','crowdstrike','a'.repeat(32),'environment:FALCON');await command('route-inventory',ca);
 const sameConnection=await bind('B','crowdstrike','b'.repeat(32),'environment:FALCON');
 await assert.rejects(()=>command('route-inventory',sameConnection),e=>e.code==='23505');
 const sameCid=await bind('B','crowdstrike','a'.repeat(32),'environment:FALCON_2');
 await assert.rejects(()=>command('route-inventory',sameCid),e=>e.code==='23505');
 const cb=await bind('B','crowdstrike','b'.repeat(32),'environment:FALCON_2');await command('route-inventory',cb);
 assert.deepEqual((await routing.read('crowdstrike',collect)).map(r=>[r.companyId,r.connectionRef,r.sourceScope]),[['A','environment:FALCON','a'.repeat(32)],['B','environment:FALCON_2','b'.repeat(32)]]);
 ok('Falcon approvals enforce both one owner per CID and one CID/customer per configured connection');

 const path=join(dir,'export.json');await run(['export-inventory-routes','--company','A','--output',path]);
 const exported=JSON.parse(await readFile(path,'utf8'));assert.equal(exported.routes.length,4);
 assert.ok(exported.routes.every(r=>r.companyId==='A'&&r.expectedRevision===1));
 assert.doesNotMatch(JSON.stringify(exported),new RegExp(tenant+'|source_scope|fixture|password|companyId":"B'));
 await assert.rejects(()=>run(['export-inventory-routes','--company','A','--output',path]),e=>e.code==='EEXIST');
 ok('private route export is customer scoped, contains no vendor scope or secrets, and cannot overwrite prior evidence');

 const bad=await bind('B','intune',tenant);
 await assert.rejects(()=>command('route-inventory',bad),e=>e.code==='23505');
 const collision=await bind('B','automate','17');collision.expectedRevision=1;
 await assert.rejects(()=>command('route-inventory',collision),e=>e.code==='23505');
 assert.equal((await db.query("SELECT revision FROM customer_inventory_routes WHERE provider='automate' AND company_id='B'")).rows[0].revision,1);
 const repaired=await bind('B','automate','18');repaired.expectedRevision=1;await command('route-inventory',repaired);
 const sf=await bind('A','spiderfoot',null);
 await assert.rejects(()=>command('route-inventory',sf),/not supported/);
 await assert.rejects(()=>command('route-inventory',{...a,expectedRevision:0,companyId:'UNKNOWN'}),/binding changed/);
 await assert.rejects(()=>command('route-inventory',{...a,expectedRevision:1,privateKey:'must not be accepted'}),/Invalid inventory/);
 ok('one active source scope cannot belong to two customers; conflicts roll back and unsupported roles and fields fail');

 const edit={...a,expectedRevision:1};const fixed=await collect();
 const attempts=await Promise.allSettled([routing.save(edit,'fixture',async()=>fixed),routing.save(edit,'fixture',async()=>fixed)]);
 assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);
 assert.match(String(attempts.find(r=>r.status==='rejected').reason),/routing changed/);
 const audits=Number((await db.query('SELECT count(*) n FROM customer_inventory_route_audit')).rows[0].n);
 await db.query("CREATE FUNCTION reject_route_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$; CREATE TRIGGER reject_route BEFORE INSERT ON customer_inventory_route_audit FOR EACH ROW EXECUTE FUNCTION reject_route_audit()");
 await assert.rejects(()=>routing.save({...a,expectedRevision:2},'fixture',collect),/fixture audit failure/);
 assert.equal((await routing.exportCustomer('A')).routes.find(r=>r.provider==='automate').expectedRevision,2);
 assert.equal(Number((await db.query('SELECT count(*) n FROM customer_inventory_route_audit')).rows[0].n),audits);
 await db.query('DROP TRIGGER reject_route ON customer_inventory_route_audit; DROP FUNCTION reject_route_audit()');
 ok('competing approvals accept one revision; audit failure rolls back approval and revision atomically');

 const changed=await bind('A','automate','19');changed.expectedRevision=2;
 await assert.rejects(()=>routing.read('automate',collect),/renewed approval/);
 await command('route-inventory',changed);
 assert.equal((await routing.read('automate',collect))[0].sourceScope,'19');
 env.AUTOMATE_BASE_URL='https://changed.invalid';
 await assert.rejects(()=>routing.read('automate',collect),/current review/);
 await assert.rejects(()=>command('route-inventory',{...changed,expectedRevision:3}),/current review/);
 await routing.save({...changed,expectedRevision:3,enabled:false},'fixture',async()=>{throw Error('No metadata access needed to disable');});
 assert.equal((await routing.exportCustomer('A')).routes.find(r=>r.provider==='automate').enabled,false);
 // A different customer's stale enabled route still stops the whole provider.
 await assert.rejects(()=>routing.read('automate',collect),/current review/);
 await command('route-inventory',{...repaired,expectedRevision:2,enabled:false});
 assert.deepEqual(await routing.read('automate',collect),[]);
 ok('assignment/configuration changes require renewed approval; one stale route stops the batch; revocation works despite stale evidence');

 // Deleted and demo destinations are rejected against current company metadata.
 await db.query("UPDATE vuln_store SET data=$1 WHERE key='meta'",[{companies:companies.filter(([id])=>id!=='A')}]);
 await assert.rejects(()=>routing.read('intune',collect),/current review/);
 await db.query("UPDATE vuln_store SET data=$1 WHERE key='meta'",[{companies:companies.map(([id,c])=>[id,id==='A'?{...c,isDemo:true}:c])}]);
 await assert.rejects(()=>routing.read('intune',collect),/current review/);
 await command('route-inventory',{...i,expectedRevision:1,enabled:false});
 assert.deepEqual(await routing.read('intune',collect),[]);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 assert.equal((await db.query("SELECT count(*)::int n FROM vuln_store WHERE key!='meta'")).rows[0].n,0);
 ok('removed/demo customers cannot receive routed imports; revocation does not migrate, delete or publish platform data');
 console.log(JSON.stringify({checks,passed:true,productionWrites:false,externalCalls:false}));
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();}
