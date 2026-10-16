// Synthetic data only, in a fresh database on the private socket-only test cluster.
import assert from 'node:assert/strict';
import { readFile, realpath } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';

const socket = await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'));
const options = {host:socket,port:55483,user:'codex',connectionTimeoutMillis:5000,statement_timeout:15000};
const admin = new pg.Client({...options,database:'postgres'});
const name = `cve_index_test_${randomUUID().replaceAll('-','')}`, run = randomUUID();
let db, created = false;
try {
  await admin.connect();
  const isolation = (await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/') && !isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`); created = true;
  db = new pg.Client({...options,database:name}); await db.connect();
  await db.query(`CREATE TABLE spotlight_import_records(run_id uuid,tenant_key text,company_id text,source_id text,cve text,status text,observed_at timestamptz,raw jsonb,PRIMARY KEY(run_id,tenant_key,source_id));
    CREATE TABLE patch_group_ticket_requests(id integer PRIMARY KEY,cves jsonb);
    INSERT INTO patch_group_ticket_requests VALUES(1,'["CVE-2026-1234"]'),(2,'["CVE-2026-9999"]');`);
  await db.query(`INSERT INTO spotlight_import_records
    SELECT $1::uuid,CASE WHEN n%2=0 THEN 'CO-A' ELSE 'CO-B' END,
      CASE WHEN n%2=0 THEN 'CO-A' ELSE 'CO-B' END,lpad(n::text,8,'0'),
      'CVE-2026-'||(1000+n%1000),CASE WHEN n%3=0 THEN 'closed' WHEN n%3=1 THEN 'open' ELSE 'reopen' END,
      now(),jsonb_build_object('fixture',repeat('x',500)) FROM generate_series(1,40000) n`,[run]);
  await db.query('ANALYZE spotlight_import_records');
  const service = await readFile('lib/customer-cve-service.ts','utf8');
  const sql = service.match(/`(SELECT r.company_id,r.source_id,r.cve,r.status,r.raw,r.observed_at[\s\S]*?LIMIT \$3)`/)[1];
  const params = ['CO-A','CVE-2026-1234',10001,run];
  const before = (await db.query(sql,params)).rows;
  assert.ok(before.length > 0);
  const migration = (await readFile('docs/sql/remediation-read-indexes.sql','utf8')).replace(/^--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean);
  // Reapplying a successful operator migration must preserve records/results.
  for(let pass=0;pass<2;pass++)for(const statement of migration)await db.query(statement);
  const indexes = (await db.query(`SELECT c.relname,i.indisvalid,i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
    WHERE c.relname IN ('spotlight_import_customer_cve_open','patch_group_ticket_cves_gin') ORDER BY c.relname`)).rows;
  assert.equal(indexes.length,2); assert.ok(indexes.every(i=>i.indisvalid && i.indisready));
  assert.deepEqual((await db.query(sql,params)).rows,before);
  assert.ok(before.every(row=>row.company_id==='CO-A' && row.cve==='CVE-2026-1234' && ['open','reopen'].includes(row.status)));
  const plan = (await db.query('EXPLAIN (FORMAT JSON) '+sql,params)).rows[0]['QUERY PLAN'][0].Plan;
  const nodes = []; function visit(node){nodes.push(node);for(const child of node.Plans??[])visit(child);} visit(plan);
  const indexed = nodes.find(node=>node['Index Name']==='spotlight_import_customer_cve_open');
  assert.ok(indexed,'the actual CVE service query must use the selective index');
  assert.match(indexed['Index Cond'],/cve =/);
  assert.deepEqual((await db.query("SELECT id FROM patch_group_ticket_requests WHERE cves @> jsonb_build_array($1::text)",['CVE-2026-1234'])).rows,[{id:1}]);
  console.log(JSON.stringify({passed:true,checks:5,fixtureRows:40000,matchedRows:before.length,index:indexed['Index Name'],productionWrites:false}));
} finally {
  if(db)await db.end();
  if(created)await admin.query(`DROP DATABASE ${name}`);
  await admin.end();
}
