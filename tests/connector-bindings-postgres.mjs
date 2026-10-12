import assert from 'node:assert/strict';
import { readFile,writeFile,realpath,mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { runRegistry } from '../scripts/customer-connector-registry.mjs';
import { loadConnectorPreview,loadConnectorBindingStore,loadSavedSourceBindings } from '../scripts/connector-preview-loader.mjs';
import { loadDefenderSourceReader } from '../scripts/source-read-model-loader.mjs';
import { readApplicationConnectorMetadata,readDashboardConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const socket=await realpath(process.argv[2]||'.');assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const name=`vuln2_bindings_test_${randomUUID().replaceAll('-','')}`,admin=new pg.Client({...config,database:'postgres'});
let db,pool,created=false,checks=0;const ok=message=>{checks++;console.log('PASS '+message);};
const dir=await mkdtemp(join(tmpdir(),'vuln-bindings-'));
try {
  await admin.connect();const state=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
  assert.ok(state.data.startsWith('/home/codex/vuln-recovery/')&&!state.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;
  db=new pg.Client({...config,database:name});await db.connect();pool=new pg.Pool({...config,database:name,max:4});
  await db.query(await readFile('docs/sql/customer-connector-drafts.sql','utf8'));
  await db.query(`CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb);
    CREATE TABLE defender_connections(company_id text PRIMARY KEY,tenant_id text,revision int);
    CREATE TABLE elastic_dashboard_connection(id int PRIMARY KEY,revision int);
    CREATE TABLE elastic_dashboard_queries(id text PRIMARY KEY,revision int,definition jsonb);`);
  await db.query("INSERT INTO vuln_store VALUES('meta',$1)",[JSON.stringify({companies:[['A',{id:'A',name:'Alpha'}],['B',{id:'B',name:'Beta'}]]})]);
  await db.query("INSERT INTO defender_connections VALUES('A','private-a',1); INSERT INTO elastic_dashboard_connection VALUES(1,1)");
  await db.query("INSERT INTO elastic_dashboard_queries VALUES('tile-a',1,$1)",[{companyId:'A',source:'elastic'}]);
  const url=new URL(`postgresql://codex@localhost/${name}`);url.searchParams.set('host',socket);url.searchParams.set('port','55483');
  const env={DATABASE_URL:url.href,SPIDERFOOT_URL:'https://not-contacted.invalid'};
  const run=args=>runRegistry(args,env),build=await loadConnectorPreview();
  const collect=async()=>build({...await readApplicationConnectorMetadata(db),...await readDashboardConnectorMetadata(db)},env);
  const store=(await loadConnectorBindingStore())(pool);
  await run(['import','--fingerprint',(await collect()).fingerprint]);
  await assert.rejects(()=>store.list('A',collect),e=>e.code==='42P01');
  await db.query(await readFile('docs/sql/customer-connector-bindings.sql','utf8'));
  const exported=async(company)=>{const path=join(dir,randomUUID()+'.json');await run(['export-bindings','--company',company,'--output',path]);return JSON.parse(await readFile(path,'utf8'));};
  const a=await exported('A'),b=await exported('B');assert.doesNotMatch(JSON.stringify(b),/private-a|tile-a/);
  const request=(data,provider,kind)=>structuredClone(data.items.find(i=>i.provider===provider&&(!kind||i.capabilities.includes(kind))).assignmentRequest);
  const sa=request(a,'spiderfoot'),sb=request(b,'spiderfoot');
  for(const [input,target] of [[sa,'alpha.fixture.test'],[sb,'beta.fixture.test']]){
    input.decision='reviewed';input.note='Synthetic approved target.';input.proposal.authority='findings-primary';input.proposal.targets=[target];
    const path=join(dir,randomUUID()+'.json');await writeFile(path,JSON.stringify(input),{mode:0o600});
    assert.equal((await run(['assign','--input',path])).enabledBindings,0);
  }
  const rows=(await db.query('SELECT * FROM customer_connector_bindings ORDER BY company_id')).rows;
  assert.equal(rows.length,2);assert.equal(rows[0].candidate_id,rows[1].candidate_id);
  assert.deepEqual(rows.map(r=>r.proposal.targets[0]),['alpha.fixture.test','beta.fixture.test']);
  assert.doesNotMatch(JSON.stringify(await exported('A')),/beta.fixture.test/);
  assert.doesNotMatch(JSON.stringify(await exported('B')),/alpha.fixture.test/);
  assert.equal((await db.query('SELECT proposal FROM customer_connector_drafts WHERE id=$1',[sa.candidateId])).rows[0].proposal.companyId,null);
  ok('actual commands assign one shared scanner to two customers without changing its evidence or leaking targets');

  const edit=request(await exported('A'),'spiderfoot');edit.note='Synthetic edit';edit.proposal.targets=['alpha-new.fixture.test'];
  // Serialized collection uses a dedicated client per call in the real CLI; use
  // a fixed trusted snapshot here to exercise competing registry transactions.
  const fixed=await collect();const attempts=await Promise.allSettled([store.save(edit,'fixture',async()=>fixed),store.save(edit,'fixture',async()=>fixed)]);
  assert.equal(attempts.filter(v=>v.status==='fulfilled').length,1);
  assert.match(String(attempts.find(v=>v.status==='rejected').reason),/Binding changed/);
  assert.deepEqual(request(await exported('B'),'spiderfoot').proposal.targets,['beta.fixture.test']);
  ok('concurrent edits accept one revision and never change the other customer');

  const defender=request(a,'defender');defender.companyId='B';defender.proposal.companyId='B';defender.note='Wrong owner';
  await assert.rejects(()=>store.save(defender,'fixture',collect),/different customer/);
  await assert.rejects(()=>store.save({...sa,companyId:'B'},'fixture',collect),/customer cannot/);
  await assert.rejects(()=>store.save({...sa,enabled:true},'fixture',collect),/Unexpected binding fields/);
  await assert.rejects(()=>store.save({...sa,companyId:'UNKNOWN',proposal:{...sa.proposal,companyId:'UNKNOWN'}},'fixture',collect),/non-demo/);
  const invalid=request(await exported('B'),'spiderfoot');invalid.decision='reviewed';invalid.note='Missing targets';invalid.proposal.targets=[];
  await assert.rejects(()=>store.save(invalid,'fixture',collect),/Record the verified|scanner targets/);
  await assert.rejects(()=>db.query('UPDATE customer_connector_bindings SET enabled=true'),e=>e.code==='23514');
  ok('ownership, customer identity, source capability, unknown fields and activation are enforced');

  const elasticA=request(a,'elastic','saved-query');elasticA.note='Synthetic query scope';elasticA.decision='reviewed';elasticA.proposal.authority='query-only';elasticA.proposal.datasets=['alpha-*'];
  await store.save(elasticA,'fixture',collect);
  await db.query('UPDATE elastic_dashboard_connection SET revision=2');
  const stale=(await exported('A')).items.find(i=>i.candidateId===elasticA.candidateId);assert.equal(stale.state,'needs-review');assert.equal(stale.importRequired,true);
  await assert.rejects(()=>store.save({...stale.assignmentRequest,note:'Changed source'},'fixture',collect),/Source metadata changed/);
  await run(['import','--fingerprint',(await collect()).fingerprint]);
  const latest=(await exported('A')).items.find(i=>i.candidateId===elasticA.candidateId);assert.equal(latest.state,'needs-review');assert.equal(latest.importRequired,false);
  await store.save({...latest.assignmentRequest,decision:'reviewed',note:'Reverified query scope'},'fixture',collect);
  ok('source revision changes invalidate bindings and require import plus independent customer review');

  const current=request(await exported('A'),'spiderfoot');current.note='Rollback fixture';
  const count=Number((await db.query('SELECT count(*) n FROM customer_connector_binding_audit')).rows[0].n);
  await db.query("CREATE FUNCTION reject_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$; CREATE TRIGGER reject_binding BEFORE INSERT ON customer_connector_binding_audit FOR EACH ROW EXECUTE FUNCTION reject_binding_audit()");
  await assert.rejects(()=>store.save(current,'fixture',collect),/fixture audit failure/);
  assert.equal(request(await exported('A'),'spiderfoot').expectedRevision,current.expectedRevision);
  assert.equal(Number((await db.query('SELECT count(*) n FROM customer_connector_binding_audit')).rows[0].n),count);
  await db.query('DROP TRIGGER reject_binding ON customer_connector_binding_audit; DROP FUNCTION reject_binding_audit()');
  ok('failed audit rolls back assignment changes atomically');

  const tile=(await collect()).candidates.find(c=>c.tileId==='tile-a');
  const tileInput=(await exported('A')).items.find(i=>i.candidateId===tile.id).assignmentRequest;
  await store.save({...tileInput,note:'Synthetic owned query',decision:'reviewed',proposal:{...tileInput.proposal,datasets:['alpha-*'],authority:'query-only'}},'fixture',collect);
  await db.query("UPDATE elastic_dashboard_queries SET definition=$1,revision=2 WHERE id='tile-a'",[{companyId:'B',source:'elastic'}]);
  const moved=(await exported('A')).items.find(i=>i.candidateId===tile.id);assert.equal(moved.state,'ownership-changed');assert.equal(moved.assignmentRequest,null);
  assert.doesNotMatch(JSON.stringify(moved),/companyId|datasets|tenantId/);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
  ok('changed tile ownership hides the new owner and cannot become an active source');

  const select=(await loadSavedSourceBindings()).createSavedSourceBindingSelector(pool,env);
  assert.deepEqual((await select('A')).sources,[]);
  const da=request(await exported('A'),'defender');da.note='Synthetic saved Defender scope';da.decision='reviewed';da.proposal.authority='findings-primary';
  await store.save(da,'fixture',collect);
  assert.deepEqual((await select('A')).sources,['defender']);
  assert.deepEqual((await select('B')).sources,[]);
  await assert.rejects(()=>select('UNKNOWN'),e=>e.status===404);
  ok('reviewed customer binding selects the real saved reader without selecting another customer or query');

  await db.query(`ALTER TABLE defender_connections ADD COLUMN current_run uuid;
    CREATE TABLE defender_import_runs(id uuid PRIMARY KEY,company_id text,revision int,status text,summary jsonb,started_at timestamptz,finished_at timestamptz);
    CREATE TABLE defender_cves(run_id uuid,cve text,severity text,severity_rank int,cvss double precision,devices int,findings int,PRIMARY KEY(run_id,cve));`);
  const importId=randomUUID();
  await db.query("INSERT INTO defender_import_runs VALUES($1,'A',1,'succeeded',$2,now(),now())",[importId,{findings:1,cves:1,affectedDevices:1,inventoryDevices:1,severity:{CRITICAL:1}}]);
  await db.query("INSERT INTO defender_cves VALUES($1,'CVE-2026-1000','CRITICAL',6,9.8,1,1)",[importId]);
  await db.query("UPDATE defender_connections SET current_run=$1 WHERE company_id='A'",[importId]);
  const reader=(await loadDefenderSourceReader())(pool),selection=await select('A');
  const read=()=>reader({companyId:'A',now:new Date(),staleAfterMs:3600000,defenderConnection:selection.defenderConnection});
  assert.equal((await read()).state,'available');
  await db.query("UPDATE defender_connections SET tenant_id='private-new',revision=2 WHERE company_id='A'");
  assert.equal((await read()).state,'inconsistent');
  const staleSelection=await select('A');assert.deepEqual(staleSelection.sources,[]);
  assert.doesNotMatch(JSON.stringify(staleSelection),/private-new|private-a/);
  ok('tenant change between selection and SQL read withholds old results; next selection requires review');

  await run(['import','--fingerprint',(await collect()).fingerprint]);
  const reviewed=request(await exported('A'),'defender');reviewed.note='Synthetic new connection review';reviewed.decision='reviewed';
  reviewed.proposal.tenantId='private-new';reviewed.proposal.authority='findings-primary';
  await store.save(reviewed,'fixture',collect);
  const nextSelection=await select('A');assert.deepEqual(nextSelection.sources,['defender']);
  const nextRequest={companyId:'A',now:new Date(),staleAfterMs:3600000,defenderConnection:nextSelection.defenderConnection};
  assert.equal((await reader(nextRequest)).state,'inconsistent');
  const freshId=randomUUID();
  await db.query("INSERT INTO defender_import_runs VALUES($1,'A',2,'succeeded',$2,now(),now())",[freshId,{findings:0,cves:0,affectedDevices:0,inventoryDevices:1,severity:{}}]);
  await db.query("UPDATE defender_connections SET current_run=$1 WHERE company_id='A'",[freshId]);
  const fresh=await reader(nextRequest);assert.equal(fresh.state,'available');assert.equal(fresh.summary.sourceInstances,0);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
  ok('reviewing a new connection cannot reuse its old import; a matching completed generation becomes readable');

  Object.assign(env,{
    NESSUS_URL:'https://fixture.invalid',NESSUS_ACCESS_KEY:'fixture',NESSUS_SECRET_KEY:'fixture',
    ARTEMIS_API_URL:'https://fixture.invalid',ARTEMIS_API_TOKEN:'fixture',ZAP_URL:'https://fixture.invalid',ZAP_API_KEY:'fixture',
    BURP_API_URL:'https://fixture.invalid',BURP_API_KEY:'fixture',NMAP_RUNNER_URL:'https://fixture.invalid',NMAP_RUNNER_TOKEN:'fixture',
    VULNERS_API_KEY:'fixture',TIDAL_EMAIL:'fixture',TIDAL_PASSWORD:'fixture',
    INTUNE_TENANT_ID:'tenant-intune',INTUNE_CLIENT_ID:'fixture',INTUNE_CLIENT_SECRET:'fixture',
    AUTOMATE_BASE_URL:'https://fixture.invalid',AUTOMATE_API_CLIENT_ID:'fixture',AUTOMATE_USERNAME:'fixture',AUTOMATE_PASSWORD:'fixture',
    MISP_URL:'https://fixture.invalid',MISP_API_KEY:'fixture',OPENCTI_URL:'https://fixture.invalid',OPENCTI_API_KEY:'fixture',
    INTELOWL_URL:'https://fixture.invalid',INTELOWL_API_KEY:'fixture',APPSEC_ELASTIC_URL:'https://fixture.invalid',APPSEC_ELASTIC_API_KEY:'fixture',
    N8N_MCP_URL:'https://fixture.invalid',QUALYS_API_URL:'https://fixture.invalid',QUALYS_USERNAME:'fixture',QUALYS_PASSWORD:'fixture'
  });
  await run(['import','--fingerprint',(await collect()).fingerprint]);
  for(const [provider,role] of [
    ...['nessus','artemis','zap','burp','nmap','vulners'].map(p=>[p,'findings-primary']),
    ...['tidal','intune','automate'].map(p=>[p,'inventory']),
    ...['misp','opencti','intelowl'].map(p=>[p,'enrichment']),['appsec','query-only']]) {
    for(const company of ['A','B']) {
      const input=request(await exported(company),provider);input.decision='reviewed';input.note='Synthetic scope contract';
      input.proposal.authority=role;input.proposal.targets=['customer-'+company+'.fixture.test'];
      if(role==='query-only')input.proposal.datasets=['customer-'+company+'-*'];
      await store.save(input,'fixture',collect);
    }
    const saved=(await db.query('SELECT company_id,proposal FROM customer_connector_bindings WHERE candidate_id=$1 ORDER BY company_id',[request(await exported('A'),provider).candidateId])).rows;
    assert.equal(saved.length,2);assert.deepEqual(saved.map(r=>r.proposal.authority),[role,role]);
    assert.deepEqual(saved.map(r=>r.proposal.targets),[['customer-A.fixture.test'],['customer-B.fixture.test']]);
  }
  assert.doesNotMatch(JSON.stringify(await exported('A')),/customer-B.fixture.test|customer-B-\*/);
  for(const provider of ['n8n','qualys']) {
    const input=request(await exported('A'),provider);input.decision='reviewed';input.note='Unsupported findings authority';input.proposal.authority='findings-primary';
    await assert.rejects(()=>store.save(input,'fixture',collect));
  }
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_bindings WHERE enabled')).rows[0].n,0);
  ok('scanner, inventory, enrichment and AppSec scopes persist independently per customer; orchestration and planned sources cannot claim findings');
  console.log(JSON.stringify({checks,passed:true,productionWrites:false,externalCalls:false}));
}finally{await pool?.end();await db?.end();if(created)await admin.query(`DROP DATABASE ${name}`);await admin.end();}
