// Guarded disposable database on the isolated recovery cluster. No production or vendor calls.
import assert from 'node:assert/strict';
import {readFile,writeFile,realpath,mkdtemp} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {randomUUID} from 'node:crypto';
import {SourceTextModule,SyntheticModule} from 'node:vm';import ts from 'typescript';import pg from 'pg';
import {runRegistry} from '../scripts/customer-connector-registry.mjs';
import {loadConnectorPreview,loadConnectorBindingStore,loadSpotlightRouting} from '../scripts/connector-preview-loader.mjs';
import {readApplicationConnectorMetadata} from '../lib/db/connector-metadata.mjs';
globalThis.fetch=()=>{throw Error('Unexpected vendor operation');};
const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_spotlight_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=m=>{checks++;console.log('PASS '+m);};
const dir=await mkdtemp(join(tmpdir(),'vuln-spotlight-'));
try {
 await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
 assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);
 await admin.query(`CREATE DATABASE ${name}`);created=true;
 db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:4});
 const mod=new SourceTextModule(ts.transpileModule(await readFile('lib/spotlight-record-store.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
 await mod.link(async spec=>{const values=spec==='./persist'?{applicationDatabase:()=>{throw Error('Unexpected runtime database');}}:await import(spec);
  return new SyntheticModule(Object.keys(values),function(){for(const k of Object.keys(values))this.setExport(k,values[k]);});});await mod.evaluate();
 const records=mod.namespace.createSpotlightRecordStore(pool);
 await records.beginOrResumePartitionedSpotlightRun('LEGACY',['open']); // Existing source schema, fixture only.
 await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
 await db.query('CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb)');
 await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}]]})]);
 const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
 const env={DATABASE_URL:url.href,FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:'Alpha',
  FALCON_CLIENT_ID_2:'fixture2',FALCON_CLIENT_SECRET_2:'fixture',FALCON_CUSTOMER_2:'Beta'};
 const build=await loadConnectorPreview(),core=await loadSpotlightRouting(),routing=core.createSpotlightRoutingStore(pool),bindings=(await loadConnectorBindingStore())(pool);
 const collect=async()=>build({...await readApplicationConnectorMetadata(db),connections:[],tiles:[]},env);
 const run=args=>runRegistry(args,env);
 const command=async(cmd,input)=>{const file=join(dir,randomUUID()+'.json');await writeFile(file,JSON.stringify(input),{mode:0o600});return run([cmd,'--input',file]);};
 await run(['import','--fingerprint',(await collect()).fingerprint]);
 await assert.rejects(()=>routing.read('crowdstrike',collect),e=>e.code==='42P01');
 assert.equal((await db.query("SELECT to_regclass('customer_spotlight_routes') n")).rows[0].n,null);
 await db.query(await readFile('docs/sql/customer-inventory-routes.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-inventory-routes-v2.sql','utf8'));
 await db.query(await readFile('docs/sql/customer-spotlight-routes.sql','utf8'));
 assert.deepEqual(await routing.read('crowdstrike',collect),[]);ok('explicit migration only; missing route tables never self-initialize');
 async function bind(company,cid,authority='findings-primary') {
  const input=structuredClone((await bindings.list(company,collect)).items.find(i=>i.provider==='crowdstrike'&&i.connectionRef===(company==='A'?'environment:FALCON':'environment:FALCON_2')).assignmentRequest);
  Object.assign(input,{decision:'reviewed',note:'Fixture source ownership',proposal:{companyId:company,tenantId:cid,authority,datasets:[],targets:[]}});
  const result=await command('assign',input);
  return {candidateId:input.candidateId,companyId:company,bindingRevision:result.revision,expectedRevision:0,enabled:true,note:'Fixture findings approval'};
 }
 let input=await bind('A','a'.repeat(32),'inventory');await assert.rejects(()=>command('route-spotlight',input),/primary findings/);
 input=await bind('A','a'.repeat(32));assert.deepEqual(await routing.read('crowdstrike',collect),[]);
 await command('route-spotlight',input);
 const duplicate=await bind('B','a'.repeat(32));await assert.rejects(()=>command('route-spotlight',duplicate),e=>e.code==='23505');
 await assert.rejects(()=>command('route-spotlight',input),/changed/);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_spotlight_route_audit')).rows[0].n,1);
 assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
 await assert.rejects(()=>command('route-inventory',duplicate),e=>e.code==='23505');
 await command('route-inventory',input);
 const matchingInventory=(await db.query("SELECT company_id,source_scope FROM customer_inventory_routes WHERE enabled")).rows;
 assert.deepEqual(matchingInventory,[{company_id:'A',source_scope:'a'.repeat(32)}]);
 // Temporarily revoke Spotlight while inventory still owns this CID: the reverse approval must also fail.
 await command('route-spotlight',{...input,expectedRevision:1,enabled:false});
 await assert.rejects(()=>command('route-spotlight',duplicate),e=>e.code==='23505');
 await command('route-spotlight',{...input,expectedRevision:2});
 ok('inventory and Spotlight approvals cannot disagree about CID/customer ownership in either direction');
 const output=join(dir,'export.json');await run(['export-spotlight-routes','--company','A','--output',output]);
 assert.equal(JSON.parse(await readFile(output,'utf8')).routes[0].expectedRevision,3);
 await assert.rejects(()=>run(['export-spotlight-routes','--company','A','--output',output]),e=>e.code==='EEXIST');
 ok('real CLI requires a separate audited primary-finding approval, rejects duplicate CID and stale edits, exports privately');
 const getScope=async()=>{const r=(await routing.read('crowdstrike',collect))[0];return {...r,cid:r.sourceScope};};
 let scope=await getScope();
 const legacy=await records.beginOrResumePartitionedSpotlightRun('A',['open']);
 let job=await records.beginOrResumePartitionedSpotlightRun('A',['open'],scope);
 assert.notEqual(job.id,legacy.id);assert.equal((await records.beginOrResumePartitionedSpotlightRun('A',['open'],scope)).id,job.id);
 await assert.rejects(()=>records.beginOrResumePartitionedSpotlightRun('A',['other'],scope),/partitions changed/);
 const legacyAgain=await records.beginOrResumePartitionedSpotlightRun('A',['open']);assert.equal(legacyAgain.id,legacy.id);
 assert.equal((await records.beginOrResumePartitionedSpotlightRun('A',['open'],scope)).id,job.id);
 ok('reviewed runs resume only their exact pin; legacy runs and changed partition definitions cannot mix');
 const row=(id,raw={id,cid:scope.cid})=>({sourceId:id,tenantKey:'A',companyId:'A',hostname:'host-'+id,localIp:'',externalIp:'',cve:'CVE-2026-1234',severity:'High',status:'open',description:'Fixture',remediation:'Update',observedAt:new Date().toISOString(),raw});
 const stage=async(rows)=>{let j=await records.beginOrResumePartitionedSpotlightRun('A',['open'],scope);
  j=await records.savePartitionPage(j.id,'A','open','',rows.map(r=>r.sourceId),'',rows.length);
  await records.writeSpotlightHydrationBatch(j.id,'A',rows.map(r=>r.sourceId),rows);return j;};
 job=await stage([row('one')]);await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A'),/original reviewed scope/);
 await assert.rejects(()=>records.completeSpotlightRun(job.id,'A',1),/original reviewed scope/);
 assert.equal((await records.completeResumableSpotlightRun(job.id,'A',scope)).findingsImported,1);
 const previous=job.id,current=async()=>(await db.query("SELECT run_id FROM spotlight_import_current WHERE tenant_key='A'")).rows[0]?.run_id;
 assert.equal(await current(),previous);ok('valid reviewed generation promotes atomically; a caller cannot omit its scope');
 job=await stage([row('two')]);
 for(const bad of [{id:'two'}, {id:'two',cid:'b'.repeat(32)}, {id:'wrong',cid:scope.cid}, {id:'two',cid:null}, {id:'two',cid:123}]) {
  await db.query('UPDATE spotlight_import_records SET raw=$2 WHERE run_id=$1',[job.id,JSON.stringify(bad)]);
  await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/cannot prove/);assert.equal(await current(),previous);
 }
 await db.query("UPDATE spotlight_import_records SET raw=$2,company_id='B' WHERE run_id=$1",[job.id,JSON.stringify({id:'two',cid:scope.cid})]);
 await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/cannot prove/);
 await db.query("UPDATE spotlight_import_records SET company_id='A',status='closed',cve='CS-two',raw=$2 WHERE run_id=$1",[job.id,JSON.stringify({id:'two',unresolved:true})]);
 await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/cannot prove/);assert.equal(await current(),previous);
 ok('missing/foreign CID, wrong source ID/customer and placeholder-only generations cannot replace completed results');
 await db.query("UPDATE spotlight_import_records SET status='open',cve='CVE-2026-1234',raw=$2 WHERE run_id=$1",[job.id,JSON.stringify({id:'two',cid:scope.cid})]);
 await command('route-spotlight',{...input,expectedRevision:3,enabled:false});
 await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/approval changed/);assert.equal(await current(),previous);
 await command('route-spotlight',{...input,expectedRevision:4});scope=await getScope();
 const next=await records.beginOrResumePartitionedSpotlightRun('A',['open'],scope);assert.notEqual(next.id,job.id);
 job=await stage([row('three'),{...row('four',{id:'four',unresolved:true}),cve:'CS-four',status:'closed'}].sort((a,b)=>a.sourceId.localeCompare(b.sourceId)));
 await db.query("UPDATE spotlight_import_records SET raw=raw||$2::jsonb WHERE run_id=$1 AND source_id='four'",[job.id,JSON.stringify({extra:true})]);
 await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/cannot prove/);
 await db.query("UPDATE spotlight_import_records SET raw=$2 WHERE run_id=$1 AND source_id='four'",[job.id,JSON.stringify({id:'four',unresolved:true})]);
 assert.equal((await records.completeResumableSpotlightRun(job.id,'A',scope)).findingsImported,2);
 ok('revocation prevents promotion; renewed approval starts a fresh run; exact local placeholders may accompany verified rows');
 // Changes to a reviewed binding invalidate operational approval, including at final promotion.
 job=await stage([row('z')]);await bind('A','a'.repeat(32),'inventory');
 await assert.rejects(()=>routing.read('crowdstrike',collect),/changed|review/);
 await assert.rejects(()=>records.completeResumableSpotlightRun(job.id,'A',scope),/approval changed/);
 assert.notEqual(await current(),job.id);ok('binding edits invalidate an existing approval and block publication');
 console.log(`PASS ${checks} isolated Spotlight routing groups`);
} finally {await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
