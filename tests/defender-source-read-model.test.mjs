import assert from 'node:assert/strict';
import test from 'node:test';
import { loadDefenderSourceReader } from '../scripts/source-read-model-loader.mjs';

const create = await loadDefenderSourceReader();
const request = { companyId: 'CO-A', now: new Date('2026-10-09T12:00:00Z'), staleAfterMs: 86400000 };
const saved = () => ({ current_run: 'run-a', run_id: 'run-a', tenant_id: 'tenant-a', connection_revision: 1, import_revision: 1,
  status: 'succeeded', finished_at: '2026-10-09T00:00:00Z', latest_status: 'succeeded',
  latest_started_at: '2026-10-08T23:00:00Z', latest_finished_at: '2026-10-09T00:00:00Z',
  summary: { findings: 3, cves: 1, affectedDevices: 2, inventoryDevices: 5, severity: { HIGH: 3 } } });
function fixture(overrides = {}) {
  const data = { ready: true, saved: saved(), aggregates: [{ severity: 'HIGH', cves: '1', devices: '2', findings: '3' }],
    rows: [{ cve: 'CVE-2026-1234', severity: 'HIGH', cvss: null, devices: 2, findings: 3 }], ...overrides };
  const calls = []; let released = false;
  const reader = create({ connect: async () => ({ release() { released = true; }, async query(sql, params) {
    calls.push({ sql, params });
    if (data.fail && sql.includes(data.fail)) throw new Error('database unavailable');
    if (sql.includes('to_regclass')) return { rows: [{ ready: data.ready }] };
    if (sql.includes('LEFT JOIN LATERAL')) return { rows: data.saved ? [data.saved] : [] };
    if (sql.includes('GROUP BY severity')) return { rows: data.aggregates };
    if (sql.includes('ORDER BY severity_rank')) return { rows: data.rows };
    return { rows: [] };
  } }) });
  return { data, calls, read: extra => reader({ ...request, ...extra }), released: () => released };
}

test('source units stay separate; null scores and zero severity buckets survive', async () => {
  const f = fixture(), result = await f.read();
  assert.equal(result.state, 'available');
  assert.deepEqual([result.summary.sourceInstances, result.summary.deviceCveFindings, result.summary.uniqueCves,
    result.summary.affectedDevices, result.summary.inventoryDevices], [3, 2, 1, 2, 5]);
  assert.equal(result.cves.rows[0].cvss, null);
  assert.equal(result.summary.severity.sourceInstances.LOW, 0);
  assert.equal(result.summary.severity.uniqueCves.HIGH, 1);
  assert.equal(result.generation.freshness, 'within-window');
  assert.equal(result.generation.clock, 'import-completion');
  assert.equal(f.calls[0].sql, 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.equal(f.calls.at(-1).sql, 'COMMIT'); assert.ok(f.released());
  assert.deepEqual(f.calls.find(c => c.sql.includes('LEFT JOIN LATERAL')).params, ['CO-A']);
  assert.ok(f.calls.find(c => c.sql.includes('LEFT JOIN LATERAL')).sql.includes('r.company_id=c.company_id'));
  assert.ok(f.calls.every(c => !/FOR SHARE|FOR UPDATE|INSERT|UPDATE|CREATE|DELETE/i.test(c.sql)));
});

test('missing schema/configuration/import and corrupt ownership never fabricate zero counts', async () => {
  for (const [overrides, state] of [[{ ready: false }, 'not-installed'], [{ saved: null }, 'not-configured'],
    [{ saved: { ...saved(), current_run: null } }, 'no-completed-import'],
    [{ saved: { ...saved(), run_id: null } }, 'inconsistent'],
    [{ saved: { ...saved(), status: 'running' } }, 'inconsistent']]) {
    const result = await fixture(overrides).read();
    assert.equal(result.state, state); assert.equal(result.summary, null); assert.equal(result.cves, null);
  }
});

test('a completed empty generation is a real zero, even with inventory devices', async () => {
  const result = await fixture({ saved: { ...saved(), summary: { findings: 0, cves: 0, affectedDevices: 0, inventoryDevices: 5, severity: {} } },
    aggregates: [], rows: [] }).read();
  assert.equal(result.state, 'available'); assert.equal(result.summary.sourceInstances, 0);
  assert.equal(result.summary.inventoryDevices, 5);
});

test('stale, future, failed-latest and changed connection remain explicit without discarding completed data', async () => {
  const f = fixture({ saved: { ...saved(), connection_revision: 2, latest_status: 'failed',
    latest_started_at: '2026-10-09T08:00:00Z', latest_finished_at: '2026-10-09T09:00:00Z' } });
  const result = await f.read({ staleAfterMs: 3600000 });
  assert.equal(result.state, 'available'); assert.equal(result.generation.freshness, 'stale');
  assert.equal(result.generation.revisionMatches, false); assert.equal(result.latestAttempt.status, 'failed');
  assert.equal((await f.read({ now: new Date('2026-10-08') })).generation.freshness, 'unknown');
});

test('malformed and disagreeing summaries fail closed', async () => {
  for (const change of [{ findings: null }, { cves: 2 }, { affectedDevices: 4 }, { affectedDevices: 0 },
    { severity: { UNRECOGNIZED: 3 } }, { severity: { HIGH: 2 } }, { inventoryDevices: -1 }, { findings: '9007199254740992' }]) {
    const row = saved(); Object.assign(row.summary, change);
    assert.equal((await fixture({ saved: row }).read()).state, 'inconsistent');
  }
  assert.equal((await fixture({ rows: [] }).read()).state, 'inconsistent');
  assert.equal((await fixture({ rows: [{ cve: 'bad', severity: 'HIGH', cvss: 10, devices: 2, findings: 3 }] }).read()).state, 'inconsistent');
});

test('explicit scope and bounded page sizes are required before connecting', async () => {
  const f = fixture();
  for (const invalid of [{ companyId: '' }, { companyId: '%' }, { companyId: ' CO-A' }, { offset: -1 },
    { limit: 101 }, { limit: 0 }, { now: new Date('bad') }, { staleAfterMs: 0 }]) await assert.rejects(() => f.read(invalid));
  assert.equal(f.calls.length, 0);
  const beyond = fixture({ rows: [] }); assert.equal((await beyond.read({ offset: 10 })).cves.rows.length, 0);
});

test('database failures roll back, release, and propagate rather than returning a healthy empty state', async () => {
  const f = fixture({ fail: 'GROUP BY severity' });
  await assert.rejects(f.read, /database unavailable/);
  assert.equal(f.calls.at(-1).sql, 'ROLLBACK'); assert.ok(f.released());
});

test('registry guard prevents old tenant and revision results before any CVE read', async () => {
  const defenderConnection = {tenantId:'tenant-a',revision:1};
  assert.equal((await fixture().read({defenderConnection})).state,'available');
  for(const change of [{tenant_id:'tenant-b'},{connection_revision:2},{import_revision:2}]) {
    const f=fixture({saved:{...saved(),...change}});
    const result=await f.read({defenderConnection});
    assert.equal(result.state,'inconsistent');assert.equal(result.summary,null);
    assert.ok(f.calls.every(c=>!c.sql.includes('FROM public.defender_cves')));
  }
  const f=fixture();await assert.rejects(()=>f.read({defenderConnection:{tenantId:'',revision:0}}));
  assert.equal(f.calls.length,0);
});
