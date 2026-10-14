import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { loadSpotlightSourceReader } from '../scripts/source-read-model-loader.mjs';
const socket = await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'), 'Private restore socket required');
const options = { host: socket, port: 55483, user: 'codex', connectionTimeoutMillis: 5000, statement_timeout: 15000 };
const admin = new pg.Client({ ...options, database: 'postgres' });
const name = `vuln2_spotlight_test_${randomUUID().replaceAll('-', '')}`;
const create = await loadSpotlightSourceReader();
const request = { companyId: 'CO-A', now: new Date('2026-10-10T12:00:00Z'), staleAfterMs: 86400000 };
const a = randomUUID(), b = randomUUID(), next = randomUUID();
let db, created = false, checks = 0;
const disconnected = [], ok = message => { checks++; console.log(`PASS ${message}`); };
try {
  await admin.connect();
  const isolation = (await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/') && !isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`); created = true;
  db = new pg.Pool({ ...options, database: name, max: 3 });
  db.on('connect', client => disconnected.push(new Promise(resolve => client.once('end', resolve))));
  const read = create(db);
  assert.equal((await read(request)).state, 'not-installed');
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n, 0);
  await db.query(`CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY,tenant_key text,status text,started_at timestamptz,finished_at timestamptz,
    checkpoint_version int,expected_count bigint,hydrated_count bigint);
    CREATE TABLE spotlight_import_current(tenant_key text PRIMARY KEY,run_id uuid);
    CREATE TABLE spotlight_import_records(run_id uuid,tenant_key text,company_id text,source_id text,cve text,severity text,status text,raw jsonb,PRIMARY KEY(run_id,tenant_key,source_id));`);
  assert.equal((await read(request)).state, 'no-completed-import');
  ok('missing tables/import are distinct from a zero and never initialize schema');
  for (const [id,company] of [[a,'CO-A'],[b,'CO-B']]) {
    await db.query("INSERT INTO spotlight_import_runs VALUES($1,$2,'completed','2026-10-09','2026-10-09T01:00:00Z',3,9,9)", [id,company]);
    await db.query('INSERT INTO spotlight_import_current VALUES($1,$2)', [company,id]);
  }
  const raw = (id,cve,aid,cid,severity,score,suppression) => ({ id,aid,cid,status:'open',cve:{ id:cve,severity,base_score:score }, suppression_info:{is_suppressed:suppression} });
  const inputs = [raw('s1','CVE-2026-1000','h1','t1','CRITICAL',9.8,false),raw('s2','CVE-2026-1000','h1','t1','HIGH','7.5',false),
    raw('s3','CVE-2026-2000','h1','t1','LOW',1,undefined),raw('s4','CVE-2026-1000','h1','t2','HIGH',8,false),
    raw('s5','CVE-2026-3000','h1','t1','HIGH',8,true),{...raw('s6','CVE-2026-3000','h1','t1','HIGH',8,false),status:'closed'},
    raw('s7','CS-non-cve','h1','t1','HIGH',8,false),raw('s8','CVE-2026-2000','h2','t1','NONE',null,'true'),
    raw('s9','CVE-2026-4000','h3','t1','odd','bad',false)];
  for (const value of inputs) await db.query("INSERT INTO spotlight_import_records VALUES($1,'CO-A','CO-A',$2,$3,'Medium',$4,$5)", [a,value.id,value.cve.id,value.status,value]);
  const result = await read({ ...request, limit: 1 });
  assert.equal(result.state, 'available');
  assert.deepEqual([result.summary.sourceInstances,result.summary.deviceCveFindings,result.summary.uniqueCves,result.summary.affectedDevices], [6,5,3,4]);
  assert.equal(result.summary.inventoryDevices, null); assert.equal(result.generation.revisionMatches, null);
  assert.equal(result.summary.unknownSuppressionInstances, 2); assert.equal(result.summary.excludedSuppressedInstances, 1); assert.equal(result.summary.excludedNonCveInstances, 1);
  assert.equal(result.cves.rows[0].severity,'CRITICAL'); assert.equal(result.cves.rows[0].affectedDevices,2);
  assert.equal(result.cves.rows[0].sourceInstances,3); assert.equal(result.cves.rows[0].cvss,9.8);
  assert.equal((await read({...request,offset:2})).cves.rows[0].cvss,null);
  assert.equal(result.summary.severity.sourceInstances.UNKNOWN,1);
  assert.equal(result.generation.freshness,'stale'); assert.equal(result.generation.countVerification,'import-count-reconciled');
  ok('CVSS severity, exact suppression booleans, non-CVE exclusions, CID/aid identities, null scores and pagination are correct');
  await db.query("UPDATE spotlight_import_current SET run_id=$1 WHERE tenant_key='CO-A'",[b]);
  assert.equal((await read(request)).state,'inconsistent');
  await db.query("UPDATE spotlight_import_current SET run_id=$1 WHERE tenant_key='CO-A'",[a]);
  await db.query("UPDATE spotlight_import_records SET company_id='CO-B' WHERE source_id='s1'");
  assert.equal((await read(request)).state,'inconsistent');
  await db.query("UPDATE spotlight_import_records SET company_id='CO-A'");
  await db.query("UPDATE spotlight_import_runs SET expected_count=10 WHERE id=$1",[a]);
  assert.equal((await read(request)).state,'inconsistent');
  await db.query("UPDATE spotlight_import_runs SET expected_count=9 WHERE id=$1",[a]);
  ok('foreign generation/row and incomplete import counts fail closed');
  for (const damaged of [{...inputs[0],aid:''},{...inputs[0],status:'closed'},{...inputs[0],cve:{id:'CVE-2026-9999'}}]) {
    await db.query("UPDATE spotlight_import_records SET raw=$1 WHERE source_id='s1'",[damaged]);
    assert.equal((await read(request)).state,'inconsistent');
  }
  await db.query("UPDATE spotlight_import_records SET raw=$1 WHERE source_id='s1'",[inputs[0]]);
  ok('missing device identity and conflicting raw status/CVE cannot produce partial successful totals');
  await db.query("INSERT INTO spotlight_import_runs VALUES($1,'CO-A','failed','2026-10-10','2026-10-10T01:00:00Z',3,10,0)",[randomUUID()]);
  assert.equal((await read(request)).latestAttempt.status,'failed');
  await db.query("UPDATE spotlight_import_runs SET checkpoint_version=1 WHERE id=$1",[a]);
  assert.equal((await read(request)).generation.countVerification,'completion-marker-only');
  ok('failed newer attempt retains completed data; legacy generations expose weaker count evidence');
  let switched=false;
  const concurrent=create({connect:async()=>{const client=await db.connect();return {release:()=>client.release(),query:async(sql,values)=>{
    const response=await client.query(sql,values);
    if(!switched && sql.includes('LEFT JOIN LATERAL')) {
      switched=true;
      await db.query("INSERT INTO spotlight_import_runs VALUES($1,'CO-A','completed','2026-10-10T02:00:00Z','2026-10-10T03:00:00Z',3,0,0)",[next]);
      await db.query("UPDATE spotlight_import_current SET run_id=$1 WHERE tenant_key='CO-A'",[next]);
      await db.query('DELETE FROM spotlight_import_records WHERE run_id=$1',[a]);
    } return response;
  }};}});
  assert.equal((await concurrent(request)).summary.sourceInstances,6);
  const empty=await read(request); assert.equal(empty.state,'available'); assert.equal(empty.summary.sourceInstances,0);
  ok('concurrent publication/pruning pins old results and a completed empty replacement gives a true zero');
  const blocked=create({connect:async()=>{const client=await db.connect();return {release:()=>client.release(),query:(sql,values)=>
    sql.includes('WITH open_rows') ? client.query('DELETE FROM spotlight_import_records') : client.query(sql,values)};}});
  await assert.rejects(()=>blocked(request),error=>error.code==='25006');
  ok('PostgreSQL enforces read-only access');

  if(process.argv[3]==='--with-restored-spotlight') {
    const source=new pg.Pool({...options,database:'recovery_application',max:1,options:'-c default_transaction_read_only=on'});
    try {
      const customers=(await source.query('SELECT tenant_key FROM spotlight_import_current ORDER BY tenant_key')).rows;
      assert.ok(customers.length>0);
      for(const customer of customers) {
        const start=performance.now();
        try {
          const result=await create(source)({...request,companyId:customer.tenant_key,now:new Date(),limit:100});
          assert.equal(result.state,'available');
          console.log(JSON.stringify({restoredCompany:customer.tenant_key,adapterMs:Math.round(performance.now()-start),summary:result.summary,
            pageRows:result.cves.rows.length,freshness:result.generation.freshness,countVerification:result.generation.countVerification}));
        } catch(error) {
          if(error.code!=='57014') throw error;
          console.log(JSON.stringify({restoredCompany:customer.tenant_key,adapterMs:Math.round(performance.now()-start),performanceGate:'statement-timeout-no-partial-result'}));
        }
      }
    } finally {await source.end();}
  }
  console.log(JSON.stringify({passed:checks,productionDatabaseReads:0,productionDatabaseWrites:0}));
} finally {
  await db?.end(); await Promise.all(disconnected);
  if(created) await admin.query(`DROP DATABASE ${name}`);
  await admin.end();
}
