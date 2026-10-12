// Isolated PostgreSQL checks and opt-in aggregate parity on the private restored backup.
// No live database URL, .env, initialization, workers or vendor APIs are used.
import assert from 'node:assert/strict';
import { realpath } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { loadDefenderSourceReader } from '../scripts/source-read-model-loader.mjs';
const socket = await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'), 'Private restore socket required');
const options = { host: socket, port: 55483, user: 'codex', connectionTimeoutMillis: 5000, statement_timeout: 15000 };
const admin = new pg.Client({ ...options, database: 'postgres' });
const name = `vuln2_source_test_${randomUUID().replaceAll('-', '')}`;
const create = await loadDefenderSourceReader();
const request = { companyId: 'CO-A', now: new Date('2026-10-09T12:00:00Z'), staleAfterMs: 86400000 };
const a = randomUUID(), b = randomUUID(), next = randomUUID();
let db, created = false, checks = 0;
const disconnected = [];
const ok = message => { checks++; console.log(`PASS ${message}`); };
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
  ok('missing tables are reported without initializing a schema');
  await db.query(`CREATE TABLE defender_connections(company_id text PRIMARY KEY,revision int,current_run uuid,tenant_id text DEFAULT 'tenant-a');
    CREATE TABLE defender_import_runs(id uuid PRIMARY KEY,company_id text,revision int,status text,summary jsonb,started_at timestamptz,finished_at timestamptz);
    CREATE TABLE defender_cves(run_id uuid,cve text,severity text,severity_rank int,cvss double precision,devices int,findings int,PRIMARY KEY(run_id,cve));`);
  const summary = { findings: 3, cves: 2, affectedDevices: 1, inventoryDevices: 5, severity: { CRITICAL: 2, HIGH: 1 } };
  await db.query("INSERT INTO defender_connections(company_id,revision,current_run) VALUES ('CO-A',1,$1),('CO-B',1,$2),('CO-EMPTY',1,NULL)", [a,b]);
  for (const [id,companyId] of [[a,'CO-A'],[b,'CO-B']]) await db.query(`INSERT INTO defender_import_runs VALUES($1,$2,1,'succeeded',$3,'2026-10-09T00:00:00Z','2026-10-09T01:00:00Z')`, [id,companyId,summary]);
  await db.query(`INSERT INTO defender_cves VALUES($1,'CVE-2026-1000','CRITICAL',6,9.8,1,2),($1,'CVE-2026-2000','HIGH',5,NULL,1,1),
    ($2,'CVE-2026-9000','CRITICAL',6,10,99,99)`, [a,b]);
  const initial = await read({ ...request, limit: 1 });
  assert.equal(initial.state, 'available'); assert.equal(initial.summary.deviceCveFindings, 2);
  assert.equal(initial.summary.sourceInstances, 3); assert.equal(initial.cves.total, 2);
  assert.equal(initial.cves.rows[0].cve, 'CVE-2026-1000');
  assert.equal((await read({ ...request, offset: 1 })).cves.rows[0].cvss, null);
  assert.equal((await read({ ...request, companyId: 'CO-EMPTY' })).state, 'no-completed-import');
  assert.equal((await read({ ...request, companyId: 'CO-MISSING' })).state, 'not-configured');
  ok('counts, null scores, ordering, pages, and empty/missing connections stay customer scoped');
  await db.query("UPDATE defender_connections SET current_run=$1 WHERE company_id='CO-A'", [b]);
  assert.equal((await read(request)).state, 'inconsistent');
  await db.query("UPDATE defender_connections SET current_run=$1 WHERE company_id='CO-A'", [a]);
  ok('a pointer to another company generation fails closed');

  // Publish an empty replacement and prune old aggregates after the adapter pins metadata.
  let switched = false;
  const concurrent = create({ connect: async () => {
    const client = await db.connect();
    return { release: () => client.release(), query: async (sql, values) => {
      const result = await client.query(sql, values);
      if (!switched && sql.includes('LEFT JOIN LATERAL')) {
        switched = true;
        await db.query(`INSERT INTO defender_import_runs VALUES($1,'CO-A',1,'succeeded',$2,'2026-10-09T02:00:00Z','2026-10-09T03:00:00Z')`,
          [next, { findings: 0, cves: 0, affectedDevices: 0, inventoryDevices: 5, severity: {} }]);
        await db.query("UPDATE defender_connections SET current_run=$1 WHERE company_id='CO-A'", [next]);
        await db.query('DELETE FROM defender_cves WHERE run_id=$1', [a]);
      }
      return result;
    } };
  } });
  const pinned = await concurrent(request);
  assert.equal(pinned.state, 'available'); assert.equal(pinned.generation.id, a); assert.equal(pinned.cves.rows.length, 2);
  const replaced = await read(request);
  assert.equal(replaced.state, 'available'); assert.equal(replaced.generation.id, next); assert.equal(replaced.summary.sourceInstances, 0);
  ok('concurrent publication and pruning cannot mix generations; a new empty import replaces old counts');
  await db.query("UPDATE defender_connections SET revision=2 WHERE company_id='CO-A'");
  await db.query(`INSERT INTO defender_import_runs VALUES($1,'CO-A',2,'failed',NULL,'2026-10-09T04:00:00Z','2026-10-09T05:00:00Z')`, [randomUUID()]);
  const stale = await read({ ...request, staleAfterMs: 3600000 });
  assert.equal(stale.latestAttempt.status, 'failed'); assert.equal(stale.generation.revisionMatches, false);
  assert.equal(stale.generation.freshness, 'stale');
  ok('failed latest attempt and changed revision retain the completed generation with explicit freshness');
  // Verify PostgreSQL enforces the read-only transaction, not just code convention.
  const blocked = create({ connect: async () => {
    const client = await db.connect();
    return { release: () => client.release(), query: (sql, values) => sql.includes('GROUP BY severity')
      ? client.query('DELETE FROM defender_cves') : client.query(sql, values) };
  } });
  await assert.rejects(() => blocked(request), error => error.code === '25006');
  ok('PostgreSQL rejects accidental writes inside the adapter transaction');

  if (process.argv[3] === '--with-restored-defender') {
    const source = new pg.Pool({ ...options, database: 'recovery_application', max: 2, options: '-c default_transaction_read_only=on' });
    try {
      const connections = (await source.query('SELECT company_id FROM defender_connections WHERE current_run IS NOT NULL ORDER BY company_id')).rows;
      assert.ok(connections.length > 0);
      for (const connection of connections) {
        const timings = []; let result;
        for (let i = 0; i < 3; i++) {
          const start = performance.now();
          result = await create(source)({ ...request, companyId: connection.company_id, now: new Date(), limit: 100 });
          timings.push(Math.round((performance.now()-start)*10)/10);
          assert.equal(result.state, 'available');
        }
        const start = performance.now();
        const raw = (await source.query(`SELECT COUNT(*)::int instances,COUNT(DISTINCT cve)::int cves,
          COUNT(DISTINCT device_id)::int devices,COUNT(DISTINCT (device_id,cve))::int pairs
          FROM defender_records WHERE run_id=$1`, [result.generation.id])).rows[0];
        const inventory = (await source.query('SELECT COUNT(*)::int n FROM defender_devices WHERE run_id=$1', [result.generation.id])).rows[0].n;
        const severities = (await source.query('SELECT severity,COUNT(*)::int n FROM defender_records WHERE run_id=$1 GROUP BY severity', [result.generation.id])).rows;
        assert.deepEqual([result.summary.sourceInstances, result.summary.uniqueCves, result.summary.affectedDevices, result.summary.deviceCveFindings,
          result.summary.inventoryDevices], [raw.instances, raw.cves, raw.devices, raw.pairs, inventory]);
        for (const row of severities) assert.equal(result.summary.severity.sourceInstances[row.severity], row.n);
        // Same ranking as legacy results(), but read-only and no schema initializer.
        const oldRows = (await source.query(`SELECT cve,severity,cvss,devices,findings FROM defender_cves WHERE run_id=$1
          ORDER BY severity_rank DESC,devices DESC,cve LIMIT 100`, [result.generation.id])).rows;
        assert.deepEqual(result.cves.rows, oldRows.map(row => ({ cve: row.cve, severity: row.severity, cvss: row.cvss,
          affectedDevices: row.devices, sourceInstances: row.findings })));
        console.log(JSON.stringify({ restoredCompany: connection.company_id, sourceInstances: raw.instances, deviceCveFindings: raw.pairs,
          uniqueCves: raw.cves, affectedDevices: raw.devices, inventoryDevices: inventory,
          adapterMs: timings, rawParityAuditMs: Math.round(performance.now()-start), freshness: result.generation.freshness,
          revisionMatches: result.generation.revisionMatches, latestAttempt: result.latestAttempt?.status }));
      }
      ok('every retained Defender customer matches raw records, device/CVE grouping, severity and legacy CVE ordering');
    } finally { await source.end(); }
  }
  console.log(JSON.stringify({ passed: checks, productionReads: 0, productionWrites: 0 }));
} finally {
  await db?.end();
  // Pool.end can finish before idle clients' socket end events; wait before DROP.
  await Promise.all(disconnected);
  if (created) await admin.query(`DROP DATABASE ${name} WITH (FORCE)`);
  await admin.end();
}
