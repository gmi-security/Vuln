// Real PostgreSQL regression on a disposable database in the private test cluster.
// Never reads .env or contacts a vendor/production database.
import assert from 'node:assert/strict';
import {readFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import pg from 'pg';

const socket=await realpath(process.argv[2]||'.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/')&&socket.endsWith('/socket'));
const config={host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:30000};
const name=`spotlight_finalization_test_${randomUUID().replaceAll('-','')}`;
const admin=new pg.Client({...config,database:'postgres'});
let pool,created=false;
try {
  await admin.connect();
  const target=(await admin.query("SELECT current_setting('data_directory') data,current_setting('listen_addresses') listen")).rows[0];
  assert.ok(target.data.startsWith('/home/codex/vuln-recovery/')&&!target.listen);
  await admin.query(`CREATE DATABASE ${name}`);created=true;
  pool=new pg.Pool({...config,database:name,max:1});
  const module=new SourceTextModule(ts.transpileModule(await readFile('lib/spotlight-record-store.ts','utf8'),{
    compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},
  }).outputText);
  await module.link(async spec=>{const values=spec==='./persist'?{applicationDatabase:()=>{throw Error('Unexpected runtime database')}}:await import(spec);
    return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});});
  await module.evaluate();
  let planChecked=false,injectTimeout=false;
  const store=module.namespace.createSpotlightRecordStore({query:(...args)=>pool.query(...args),connect:async()=>{
    const client=await pool.connect();
    return {release:()=>client.release(),query:async(sql,values)=>{
      if(String(sql).includes('AS missing')){
        const plan=(await client.query('EXPLAIN (FORMAT JSON) '+sql,values)).rows[0]['QUERY PLAN'][0].Plan;
        const nodes=[];const visit=p=>{nodes.push(p);for(const child of p.Plans??[])visit(child);};visit(plan);
        assert.equal(nodes.some(p=>p['Node Type']==='Nested Loop'&&p['Join Type']==='Anti'),false,
          'Stale generation statistics must not choose a quadratic nested-loop anti-join');
        planChecked=true;
        if(injectTimeout){await client.query("SET LOCAL statement_timeout='1ms'");await client.query('SELECT pg_sleep(0.05)');}
      }
      return client.query(sql,values);
    }};
  }});
  const tenant='fixture-customer';
  const seed=await store.beginOrResumePartitionedSpotlightRun(tenant,['open']);
  await pool.query('ALTER TABLE spotlight_import_ids SET (autovacuum_enabled=false)');
  await pool.query('ALTER TABLE spotlight_import_records SET (autovacuum_enabled=false)');
  async function stage(run,number){
    await pool.query(`INSERT INTO spotlight_import_ids SELECT $1,$2,'source-'||lpad(n::text,8,'0') FROM generate_series(1,$3::int) n`,[run,tenant,number]);
    await pool.query(`INSERT INTO spotlight_import_records
      SELECT run_id,tenant_key,source_id,tenant_key,'host-'||(row_number() OVER ()%100),'','','CVE-2026-1234','High','open','','Update',now(),jsonb_build_object('id',source_id)
      FROM spotlight_import_ids WHERE run_id=$1`,[run]);
    await pool.query("UPDATE spotlight_import_runs SET phase='hydrating',expected_count=$2,hydrated_count=$2 WHERE id=$1",[run,number]);
  }
  await stage(seed.id,20000);
  await pool.query("UPDATE spotlight_import_runs SET status='completed',finished_at=now() WHERE id=$1",[seed.id]);
  await pool.query('INSERT INTO spotlight_import_current VALUES($1,$2,now())',[tenant,seed.id]);
  await pool.query('ANALYZE spotlight_import_ids');await pool.query('ANALYZE spotlight_import_records');
  const next=await store.beginOrResumePartitionedSpotlightRun(tenant,['open']);
  await stage(next.id,100000);
  const estimate=(await pool.query('EXPLAIN (FORMAT JSON) SELECT source_id FROM spotlight_import_ids WHERE run_id=$1 AND tenant_key=$2',[next.id,tenant])).rows[0]['QUERY PLAN'][0].Plan['Plan Rows'];
  assert.ok(estimate<100,'Fixture must reproduce the new-generation statistics underestimate');
  const start=Date.now();const completed=await store.completeResumableSpotlightRun(next.id,tenant);
  assert.deepEqual(completed,{findingsImported:100000,hostsAffected:100});assert.ok(planChecked);
  const current=async()=>(await pool.query('SELECT run_id FROM spotlight_import_current WHERE tenant_key=$1',[tenant])).rows[0].run_id;
  assert.equal(await current(),next.id);
  console.log(JSON.stringify({check:'stale-statistics-finalization',rows:100000,estimatedRows:estimate,ms:Date.now()-start}));
  let settings=(await pool.query("SELECT current_setting('enable_nestloop') nested,current_setting('statement_timeout') timeout")).rows[0];
  assert.deepEqual(settings,{nested:'on',timeout:'30s'});
  console.log('PASS publication and transaction-local settings reset after commit');
  const bad=await store.beginOrResumePartitionedSpotlightRun(tenant,['open']);await stage(bad.id,100);
  await pool.query("UPDATE spotlight_import_records SET source_id='unexpected-id' WHERE run_id=$1 AND source_id='source-00000001'",[bad.id]);
  await assert.rejects(()=>store.completeResumableSpotlightRun(bad.id,tenant),/count mismatch/);
  assert.equal(await current(),next.id);
  console.log('PASS equal counts with different source IDs cannot publish');
  await pool.query("UPDATE spotlight_import_records SET source_id='source-00000001' WHERE run_id=$1 AND source_id='unexpected-id'",[bad.id]);
  injectTimeout=true;
  await assert.rejects(()=>store.completeResumableSpotlightRun(bad.id,tenant),e=>e.code==='57014');
  assert.equal(await current(),next.id);
  settings=(await pool.query("SELECT current_setting('enable_nestloop') nested,current_setting('statement_timeout') timeout")).rows[0];
  assert.deepEqual(settings,{nested:'on',timeout:'30s'});
  console.log('PASS actual statement timeout retains prior publication and resets session settings');
} finally {
  await pool?.end();
  if(created)await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
  await admin.end();
}
