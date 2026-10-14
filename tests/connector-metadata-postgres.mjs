// Disposable fixture DB on the private restore cluster only; never the app DB.
import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata, readSavedApplicationCompanies } from '../lib/db/connector-metadata.mjs';
import { loadConnectorPreview } from '../scripts/connector-preview-loader.mjs';

const socket = await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'), 'Private restore socket required');
const options = { host: socket, port: 55483, user: 'codex', connectionTimeoutMillis: 5000, statement_timeout: 15000 };
const admin = new pg.Client({ ...options, database: 'postgres' });
const name = `vuln2_registry_test_${randomUUID().replaceAll('-', '')}`;
let db, created = false, checks = 0;
const ok = message => { checks++; console.log(`PASS ${message}`); };
try {
  await admin.connect();
  const isolation = (await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/') && !isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`); created = true;
  db = new pg.Client({ ...options, database: name }); await db.connect();
  let app = await readApplicationConnectorMetadata(db), dashboard = await readDashboardConnectorMetadata(db);
  assert.equal(app.coverage.companyStorage, 'none'); assert.deepEqual(dashboard.tiles, []);
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n, 0);
  ok('empty database preview creates no tables');

  await db.query(`CREATE TABLE vuln_store(key text PRIMARY KEY,data jsonb);
    CREATE TABLE vuln_snapshot(id int PRIMARY KEY,data jsonb);
    CREATE TABLE defender_connections(company_id text PRIMARY KEY,tenant_id text,revision int,secret text);
    CREATE TABLE spotlight_import_current(tenant_key text PRIMARY KEY,run_id uuid);
    CREATE TABLE spotlight_import_runs(id uuid PRIMARY KEY,status text);
    CREATE TABLE elastic_dashboard_connection(id int PRIMARY KEY,revision int,secret text);
    CREATE TABLE dashboard_source_connections(source text PRIMARY KEY,revision int,secret text);
    CREATE TABLE elastic_dashboard_queries(id text PRIMARY KEY,revision int,definition jsonb,result jsonb,deleted_at timestamptz);`);
  await db.query("INSERT INTO vuln_store VALUES ('meta',$1),('companies:0',$2),('findings:0',$3)", [
    { version: 1 }, JSON.stringify([['CO-A', { id: 'CO-A', name: 'Alpha' }], ['CO-B', { id: 'CO-B', name: 'Beta' }]]),
    JSON.stringify([{ credential: 'DO_NOT_READ', raw: 'DO_NOT_READ' }])]);
  await db.query('INSERT INTO vuln_snapshot VALUES(1,$1)', [{ companies: [['OLD', { id: 'OLD', name: 'Obsolete' }]] }]);
  await db.query("INSERT INTO defender_connections VALUES('CO-A','tenant-a',4,'ENCRYPTED_SECRET')");
  await db.query("INSERT INTO elastic_dashboard_connection VALUES(1,2,'ELASTIC_SECRET'); INSERT INTO dashboard_source_connections VALUES('crowdstrike',3,'CS_SECRET')");
  for (const [id, definition, deleted] of [
    ['legacy', { query: 'SENSITIVE_QUERY' }, null], ['explicit', { companyId: 'CO-B', source: 'crowdstrike' }, null],
    ['cleared', { companyId: null }, null], ['deleted', { companyId: 'CO-A' }, new Date()],
  ]) await db.query('INSERT INTO elastic_dashboard_queries VALUES($1,1,$2,$3,$4)', [id, definition, { secret: 'SENSITIVE_RESULT' }, deleted]);
  const generation = randomUUID();
  await db.query("INSERT INTO spotlight_import_runs VALUES($1,'completed')", [generation]);
  await db.query("INSERT INTO spotlight_import_current VALUES('CO-B',$1)", [generation]);
  app = await readApplicationConnectorMetadata(db); dashboard = await readDashboardConnectorMetadata(db);
  assert.deepEqual(await readSavedApplicationCompanies({query:(sql,args)=>{
    assert.doesNotMatch(sql,/defender_|spotlight_|elastic_|SELECT data FROM/);
    return db.query(sql,args);
  }}),app.companies);
  assert.deepEqual(app.companies.map(c => c.id), ['CO-A', 'CO-B']); assert.equal(app.defender[0].revision, 4);
  assert.equal(app.spotlight[0].companyId, 'CO-B'); assert.equal(app.spotlight[0].runId, generation);
  assert.equal(dashboard.tiles.length, 3);
  assert.equal(dashboard.tiles.find(t => t.id === 'legacy').source, 'elastic');
  assert.ok(dashboard.connections.some(c => c.source === 'elastic'));
  assert.ok(!Object.hasOwn(dashboard.tiles.find(t => t.id === 'legacy'), 'companyId'));
  assert.equal(dashboard.tiles.find(t => t.id === 'cleared').companyId, null);
  for (const word of ['SECRET', 'SENSITIVE', 'DO_NOT_READ', 'Obsolete']) assert.ok(!JSON.stringify({ app, dashboard }).includes(word));
  ok('reads only company and connector metadata; excludes deleted tiles and credential/query/result payloads');

  const build = await loadConnectorPreview();
  const report = build({ ...app, ...dashboard }, { REPORTING_CUSTOMER_TILE_IDS: '{"CO-A":["legacy","cleared"]}' });
  assert.equal(report.candidates.find(c => c.tileId === 'legacy').companyId, 'CO-A');
  assert.equal(report.candidates.find(c => c.tileId === 'cleared').companyId, null);
  assert.ok(report.candidates.filter(c => c.tileId).every(c => c.configured));
  assert.ok(report.candidates.every(c => !c.enabled));
  const after = await readDashboardConnectorMetadata(db); assert.deepEqual(after, dashboard);
  ok('end-to-end preview preserves ownership precedence and leaves saved data unchanged');

  // PostgreSQL, not just a mock, enforces the transaction's read-only boundary.
  const wrapper = { async query(sql, values) {
    if (sql.startsWith('SELECT')) return db.query("UPDATE defender_connections SET revision=999");
    return db.query(sql, values);
  } };
  await assert.rejects(() => readApplicationConnectorMetadata(wrapper), error => error.code === '25006');
  assert.equal((await db.query('SELECT revision FROM defender_connections')).rows[0].revision, 4);
  ok('PostgreSQL refuses mutations during collection and rollback restores usable connection');

  await db.query("UPDATE vuln_store SET data=$1 WHERE key='meta'", [{ companies: [['META', { id: 'META', name: 'Meta owner' }]] }]);
  assert.equal((await readApplicationConnectorMetadata(db)).companies[0].id, 'META');
  assert.equal((await readSavedApplicationCompanies(db))[0].id,'META');
  await db.query("UPDATE vuln_store SET data='{}' WHERE key='meta'; UPDATE vuln_store SET data='{}' WHERE key='companies:0'");
  await assert.rejects(() => readApplicationConnectorMetadata(db), /Invalid company snapshot bucket/);
  await assert.rejects(() => readSavedApplicationCompanies(db), /Invalid company snapshot bucket/);
  await db.query("UPDATE vuln_store SET data=$1 WHERE key='companies:0'", [JSON.stringify([['WRONG', { id: 'CO-A', name: 'Alpha' }]])]);
  await assert.rejects(() => readApplicationConnectorMetadata(db), /Invalid saved company metadata/);
  await db.query('DELETE FROM vuln_store');
  assert.equal((await readApplicationConnectorMetadata(db)).companies[0].id, 'OLD');
  assert.equal((await readSavedApplicationCompanies(db))[0].id,'OLD');
  ok('snapshot precedence matches legacy loader; malformed shards fail instead of falling back');

  await db.query('ALTER TABLE elastic_dashboard_queries DROP COLUMN deleted_at');
  assert.equal((await readDashboardConnectorMetadata(db)).tiles.length, 4);
  await db.query("UPDATE elastic_dashboard_queries SET definition=$1 WHERE id='explicit'", [{ companyId: 42 }]);
  await assert.rejects(() => readDashboardConnectorMetadata(db), /Invalid saved tile owner/);
  await db.query('DROP TABLE spotlight_import_runs');
  await assert.rejects(() => readApplicationConnectorMetadata(db), error => error.code === '42P01');
  ok('older tile schema supported; corrupt owners or missing required source tables fail closed');
  await db.query("UPDATE elastic_dashboard_queries SET definition='{}'; INSERT INTO elastic_dashboard_queries(id,revision,definition) SELECT 'limit-'||n,1,'{}'::jsonb FROM generate_series(1,10001) n");
  await assert.rejects(() => readDashboardConnectorMetadata(db), /metadata limit exceeded/);
  ok('oversized metadata aborts without a truncated successful preview');
  console.log(JSON.stringify({ passed: checks, fixtureDatabaseRemovedOnExit: true }));
} finally {
  await db?.end();
  if (created) await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
  await admin.end();
}
