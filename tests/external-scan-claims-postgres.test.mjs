// Real PostgreSQL concurrency test. Run ONLY against an ephemeral localhost DB.
// EXTERNAL_SCAN_TEST_DATABASE_URL=postgresql://testscan:testscan@127.0.0.1:5432/testscan
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
const { Pool } = pg;
import { reserveExternalScanClaim, inspectExternalScanSlot } from '../lib/db/external-scan-claims.mjs';
import { recordExternalScanRemoteTask, flagExternalScanReconciliation, inspectExternalScanReconciliation } from '../lib/db/external-scan-reconciliation.mjs';

const raw = process.env.EXTERNAL_SCAN_TEST_DATABASE_URL;
if (!raw) throw new Error('Set EXTERNAL_SCAN_TEST_DATABASE_URL to a disposable local PostgreSQL database.');
const url = new URL(raw);
if (!['localhost','127.0.0.1','[::1]'].includes(url.hostname) ||
    !['postgres:','postgresql:'].includes(url.protocol) || url.pathname !== '/testscan')
  throw new Error('Refusing non-local or non-disposable test database.');

const payload = (letter='a', when='2026-11-05T03:00:00Z') =>
  ({dedupKey:letter.repeat(64),companyId:'CO-A',target:'host.example',nessusScanId:55,occurrenceAt:when});

test('PostgreSQL enforces durable one-at-a-time scan reservations', {timeout:30000}, async()=>{
  let pool = new Pool({connectionString:raw, max:4, connectionTimeoutMillis:5000});
  try {
    const ddl = await readFile(new URL('../docs/sql/external-scan-dispatch-claims.sql',import.meta.url),'utf8');
    await pool.query(ddl); // disposable isolated database, never production
    await pool.query(await readFile(new URL('../docs/sql/external-scan-dispatch-events.sql',import.meta.url),'utf8'));


    const race = await Promise.all([reserveExternalScanClaim(pool,payload('a')),reserveExternalScanClaim(pool,payload('b'))]);
    assert.deepEqual(race.map(x=>x.state).sort(),['busy','reserved']);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM public.external_scan_dispatch_claims')).rows[0].n,1);

    const first = (await inspectExternalScanSlot(pool)).claim_key;
    assert.ok(first === 'a'.repeat(64) || first === 'b'.repeat(64));

    // Recreate database connections: the reservation must NOT vanish.
    await pool.end();
    pool = new Pool({connectionString:raw,max:4,connectionTimeoutMillis:5000});
    assert.equal((await reserveExternalScanClaim(pool,payload('c','2026-11-06T03:00:00Z'))).state,'busy');

    // Simulate a separately reviewed reconciliation (only in test DB).
    await pool.query('UPDATE public.external_scan_dispatch_slot SET claim_key = NULL WHERE slot_id = 1');
    const prior = first === 'a'.repeat(64) ? payload('a') : payload('b');
    assert.equal((await reserveExternalScanClaim(pool,prior)).state,'duplicate');

    // Different key for same customer/target/occurrence must hit schema UNIQUE,
    // not become a second job. The transaction must roll back.
    const other = first === 'a'.repeat(64) ? payload('b') : payload('a');
    await assert.rejects(()=>reserveExternalScanClaim(pool,other), e=>e?.code==='23505');
    assert.equal((await inspectExternalScanSlot(pool)).claim_key,null);

    // Competing transaction holds the singleton lock: NOWAIT must refuse.
    const hold = await pool.connect();
    try {
      await hold.query('BEGIN');
      await hold.query('SELECT claim_key FROM public.external_scan_dispatch_slot WHERE slot_id=1 FOR UPDATE');
      assert.equal((await reserveExternalScanClaim(pool,payload('c','2026-11-06T03:00:00Z'))).state,'busy');
    } finally {
      await hold.query('ROLLBACK');
      hold.release();
    }
    const next=await reserveExternalScanClaim(pool,payload('c','2026-11-06T03:00:00Z'));
    assert.equal(next.state,'reserved');
    assert.equal((await inspectExternalScanSlot(pool)).claim_key,'c'.repeat(64));
    // A confirmed remote task ID is durable and cannot be overwritten.
    const key='c'.repeat(64);
    assert.deepEqual(await recordExternalScanRemoteTask(pool,key,'greenbone-uuid-c'),
      {state:'remote-created',taskId:'greenbone-uuid-c',unchanged:false});
    assert.equal((await recordExternalScanRemoteTask(pool,key,'greenbone-uuid-c')).unchanged,true);
    await assert.rejects(()=>recordExternalScanRemoteTask(pool,key,'other-task'),/already exists/);
    // An uncertain launch is a HOLD, never a release or automatic retry.
    assert.equal((await flagExternalScanReconciliation(pool,key,'start response timed out')).state,'needs-reconciliation');
    const audited=await inspectExternalScanReconciliation(pool);
    assert.equal(audited.slot.claim_key,key);
    assert.equal(audited.slot.remote_task_id,'greenbone-uuid-c');
    assert.equal(audited.slot.state,'needs-reconciliation');
    assert.deepEqual(audited.events.map(e=>e.event_type),['needs-reconciliation','task-recorded']);
    await pool.end(); // simulate application restart after ambiguous remote call
    pool=new Pool({connectionString:raw,max:4,connectionTimeoutMillis:5000});
    assert.equal((await reserveExternalScanClaim(pool,payload('d','2026-11-07T03:00:00Z'))).state,'busy');
    assert.equal((await inspectExternalScanReconciliation(pool)).slot.state,'needs-reconciliation');
  
  } finally {
    await pool.end();
  }
});
