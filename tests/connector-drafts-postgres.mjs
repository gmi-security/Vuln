// Real transactions in a disposable database on the private recovery cluster.
// No app workers, upstream APIs, existing source tables or ticket delivery.
import assert from 'node:assert/strict';
import { readFile, realpath } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import pg from 'pg';
import nextEnv from '@next/env';
import { loadConnectorPreview, loadConnectorDraftStore } from '../scripts/connector-preview-loader.mjs';
import { readApplicationConnectorMetadata, readDashboardConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const socket = await realpath(process.argv[2] || '.');
assert.ok(socket.startsWith('/home/codex/vuln-recovery/') && socket.endsWith('/socket'), 'Private restore socket required');
const options = { host: socket, port: 55483, user: 'codex', connectionTimeoutMillis: 5000, statement_timeout: 15000 };
const admin = new pg.Client({ ...options, database: 'postgres' });
const name = `vuln2_drafts_test_${randomUUID().replaceAll('-', '')}`;
let db, created = false, checks = 0;
const ok = message => { checks++; console.log(`PASS ${message}`); };
const build = await loadConnectorPreview(), createStore = await loadConnectorDraftStore();
const metadata = {
  companies: [{ id: 'CO-A', name: 'Alpha' }, { id: 'CO-B', name: 'Beta' }],
  defender: [{ companyId: 'CO-A', tenantId: 'tenant-a', revision: 1 }, { companyId: 'CO-B', tenantId: 'tenant-b', revision: 1 }],
  spotlight: [{ companyId: 'CO-B', runId: randomUUID(), status: 'completed' }],
  connections: [{ source: 'elastic', revision: 1 }],
  tiles: [{ id: 'fixture-tile', source: 'elastic', companyId: 'CO-A', revision: 1 }],
};
const env = { SPIDERFOOT_URL: 'https://not-contacted.test' };
const collect = async () => build(metadata, env);
const actor = 'fixture-operator';
const resolveCompany = async id => metadata.companies.find(c => c.id === id) ?? { id, isDemo: true };
const clone = object => JSON.parse(JSON.stringify(object));
try {
  await admin.connect();
  const isolation = (await admin.query("SELECT current_setting('data_directory') AS data,current_setting('listen_addresses') AS listen")).rows[0];
  assert.ok(isolation.data.startsWith('/home/codex/vuln-recovery/') && !isolation.listen);
  await admin.query(`CREATE DATABASE ${name}`); created = true;
  db = new pg.Pool({ ...options, database: name, max: 5 });
  const store = createStore(db);
  await assert.rejects(() => store.importPreview(build(metadata, env).fingerprint, actor, collect), error => error.code === '42P01');
  assert.equal((await db.query("SELECT count(*)::int n FROM pg_tables WHERE schemaname='public'")).rows[0].n, 0);
  await db.query(await readFile('docs/sql/customer-connector-drafts.sql', 'utf8'));
  ok('service refuses missing migration and does not initialize schema');

  const first = build(metadata, env);
  const results = await Promise.all(Array.from({ length: 4 }, () => store.importPreview(first.fingerprint, actor, collect)));
  assert.equal(results.filter(r => !r.unchanged).length, 1);
  assert.equal(new Set(results.map(r => r.importId)).size, 1);
  assert.equal((await db.query('SELECT count(*)::int n FROM connector_registry_imports')).rows[0].n, 1);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_drafts')).rows[0].n, first.candidates.length);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_audit')).rows[0].n, first.candidates.length);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_drafts WHERE enabled OR review_state <> $1', ['pending-review'])).rows[0].n, 0);
  ok('four concurrent imports create one batch and one disabled draft/audit per candidate');

  const id = first.candidates.find(c => c.provider === 'defender' && c.companyId === 'CO-A').id;
  const get = async id => (await db.query('SELECT * FROM customer_connector_drafts WHERE id=$1', [id])).rows[0];
  const review = async (row, changes = {}, decision = 'reviewed', resolver = resolveCompany) => store.reviewDraft({
    id: row.id, expectedRevision: row.revision, candidateHash: row.candidate_hash, decision,
    proposal: { ...row.proposal, authority: 'findings-primary', ...changes }, note: 'Synthetic fixture scope review; no API calls.',
  }, actor, resolver);
  const initial = await get(id);
  const reviewed = await review(initial);
  assert.equal(reviewed.review_state, 'reviewed'); assert.equal(reviewed.enabled, false);
  assert.equal(reviewed.reviewed_by, actor); assert.equal(reviewed.revision, 2);
  assert.ok((await store.listCustomerDrafts('CO-A')).some(d => d.id === id));
  assert.ok(!(await store.listCustomerDrafts('CO-B')).some(d => d.id === id));
  await assert.rejects(() => store.listCustomerDrafts(''), /Explicit customer/);
  assert.equal((await store.listCustomerDrafts('CO-MISSING')).length, 0);
  const audit = (await db.query("SELECT * FROM customer_connector_audit WHERE draft_id=$1 AND action='reviewed'", [id])).rows[0];
  assert.equal(audit.before_state.reviewState, 'pending-review'); assert.equal(audit.after_state.reviewState, 'reviewed');
  ok('review records exact before/after state while remaining disabled; reads require explicit customer');

  await assert.rejects(() => review(initial), /Draft changed/);
  await assert.rejects(() => review({ ...reviewed, candidate_hash: 'a'.repeat(64) }), /Draft changed/);
  await assert.rejects(() => review(reviewed, { companyId: 'CO-B' }), /existing customer ownership/);
  await assert.rejects(() => review(reviewed, {}, 'reviewed', async id => ({ id, isDemo: true })), /non-demo/);
  await assert.rejects(() => review(reviewed, { tenantId: 'other' }), /saved tenant/);
  await assert.rejects(() => review(reviewed, { authority: 'enrichment' }), /authority supported/);
  assert.equal((await get(id)).revision, reviewed.revision);
  ok('stale editors, stale hashes, demo customers, tenant changes and ownership transfers are rejected');

  const edited = await review(reviewed, { authority: 'inventory' }, 'save-draft');
  assert.equal(edited.review_state, 'pending-review'); assert.equal(edited.reviewed_by, null);
  metadata.defender[0].revision++;
  await assert.rejects(() => store.importPreview(first.fingerprint, actor, collect), /Source metadata changed/);
  assert.equal((await get(id)).revision, edited.revision);
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  const changed = await get(id);
  assert.equal(changed.review_state, 'needs-review'); assert.equal(changed.proposal.authority, 'inventory');
  assert.equal(changed.candidate.revision, 2); assert.equal(changed.revision, edited.revision + 1);
  ok('fresh collection rejects a stale preview; changed sources preserve the human proposal and invalidate review');

  const saved = metadata.defender.shift();
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  const missing = await get(id); assert.equal(missing.source_present, false);
  assert.equal(missing.proposal.authority, 'inventory');
  await assert.rejects(() => review(missing), /Only present/);
  metadata.defender.unshift(saved);
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  const restored = await get(id); assert.equal(restored.source_present, true); assert.equal(restored.review_state, 'needs-review');
  assert.equal(restored.proposal.authority, 'inventory');
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_drafts')).rows[0].n, first.candidates.length);
  const actions = (await db.query('SELECT action FROM customer_connector_audit WHERE draft_id=$1 ORDER BY revision', [id])).rows.map(r => r.action);
  assert.ok(actions.includes('source-missing') && actions.includes('source-restored'));
  ok('missing and returning sources keep the same draft, preserve decisions and retain audit history');

  const historical = first.candidates.find(c => c.evidence === 'completed-import');
  metadata.spotlight[0].runId = randomUUID();
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  assert.equal((await get(historical.id)).candidate.runId, metadata.spotlight[0].runId);
  assert.equal((await db.query('SELECT count(*)::int n FROM customer_connector_drafts')).rows[0].n, first.candidates.length);
  await assert.rejects(async () => review(await get(historical.id)), /Only present/);
  ok('daily generation updates reuse historical evidence identity and never become a live binding');

  const tile = await get(first.candidates.find(c => c.tileId).id);
  await assert.rejects(() => review(tile, { authority: 'query-only' }), /verified tenant, dataset/);
  await assert.rejects(() => review(tile, { datasets: ['logs-customer-*'] }), /authority supported/);
  const tileReviewed = await review(tile, { datasets: ['logs-customer-*'], authority: 'query-only' });
  assert.equal(tileReviewed.enabled, false);
  const scanner = await get(first.candidates.find(c => c.provider === 'spiderfoot').id);
  await assert.rejects(() => review(scanner, { companyId: 'CO-A', tenantId: 'not-a-target' }), /scanner targets/);
  const scannerReviewed = await review(scanner, { companyId: 'CO-A', targets: ['approved.fixture.test'] });
  assert.equal(scannerReviewed.enabled, false);
  ok('tile ownership needs query scope and scanners need approved targets; neither review enables execution');

  metadata.connections[0].revision++;
  await assert.rejects(() => store.reviewCurrentDraft({
    id: tileReviewed.id, expectedRevision: tileReviewed.revision, candidateHash: tileReviewed.candidate_hash,
    decision: 'reviewed', proposal: tileReviewed.proposal, note: 'Synthetic stale connection check.',
  }, actor, collect), /Source metadata changed/);
  assert.equal((await get(tile.id)).revision, tileReviewed.revision);
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  const changedTile = await get(tile.id);
  assert.equal(changedTile.review_state, 'needs-review');
  assert.equal(changedTile.candidate.revision, tile.candidate.revision);
  assert.notEqual(changedTile.candidate_hash, tileReviewed.candidate_hash);
  assert.equal(changedTile.source_evidence[0].revision, metadata.connections[0].revision);
  assert.deepEqual(changedTile.proposal, tileReviewed.proposal);
  ok('changing a shared connection invalidates dependent tile review even when the tile definition is unchanged');

  const dismissed = await review(await get(id), {}, 'dismissed');
  assert.equal(dismissed.review_state, 'dismissed');
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  assert.equal((await get(id)).revision, dismissed.revision);
  metadata.defender[1].revision++;
  await store.importPreview(build(metadata, env).fingerprint, actor, collect);
  assert.equal((await get(id)).review_state, 'dismissed');
  ok('replayed or unrelated source imports never reopen an unchanged dismissed decision');

  const baseline = await get(id);
  const counts = async () => (await db.query(`SELECT (SELECT count(*) FROM connector_registry_imports)::int imports,
    (SELECT count(*) FROM customer_connector_audit)::int audits`)).rows[0];
  const beforeCounts = await counts();
  await db.query(`CREATE FUNCTION reject_fixture_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$;
    CREATE TRIGGER fixture_audit BEFORE INSERT ON customer_connector_audit FOR EACH ROW EXECUTE FUNCTION reject_fixture_audit()`);
  await assert.rejects(() => review(baseline, {}, 'save-draft'), /fixture audit failure/);
  assert.equal((await get(id)).revision, baseline.revision);
  metadata.defender[0].revision++;
  metadata.defender[1].revision++;
  await assert.rejects(() => store.importPreview(build(metadata, env).fingerprint, actor, collect), /fixture audit failure/);
  assert.deepEqual(await counts(), beforeCounts);
  assert.equal((await get(id)).candidate.revision, baseline.candidate.revision);
  await db.query('DROP TRIGGER fixture_audit ON customer_connector_audit; DROP FUNCTION reject_fixture_audit()');
  ok('audit failure rolls back review and the whole import batch, including source updates');

  const poisoned = clone(build(metadata, env));
  poisoned.candidates[0].privateKey = 'DO_NOT_PERSIST';
  const { fingerprint: ignored, ...body } = poisoned;
  poisoned.fingerprint = createHash('sha256').update(JSON.stringify(body)).digest('hex');
  await assert.rejects(() => store.importPreview(poisoned.fingerprint, actor, async () => poisoned), /Unexpected registry fields/);
  await assert.rejects(() => review(baseline, { privateKey: 'DO_NOT_PERSIST' }, 'save-draft'), /Unexpected registry fields/);
  assert.deepEqual(await counts(), beforeCounts);
  await assert.rejects(() => db.query('UPDATE customer_connector_drafts SET enabled=true WHERE id=$1', [id]), error => error.code === '23514');
  ok('unexpected secret fields fail before persistence and PostgreSQL forbids activation');
  if (process.argv[3] === '--with-restored-metadata') {
    // Opt-in: read existing references from the private restore and presence-only
    // configuration from the server file. Database addresses from that file are
    // never used. ALL writes still target the disposable fixture database.
    nextEnv.processEnv([{ path: '/opt/vuln/.env.local', contents: await readFile('/opt/vuln/.env.local', 'utf8'), env: {} }],
      undefined, { info() {}, error() {} }, true);
    const source = new pg.Client({ ...options, database: 'recovery_application', options: '-c default_transaction_read_only=on' });
    await source.connect();
    try {
      await db.query('TRUNCATE customer_connector_audit,customer_connector_drafts,connector_registry_imports RESTART IDENTITY');
      const recollect = async () => build({ ...await readApplicationConnectorMetadata(source), ...await readDashboardConnectorMetadata(source) }, process.env);
      const restoredPreview = await recollect();
      const imported = await store.importPreview(restoredPreview.fingerprint, actor, recollect);
      assert.equal(imported.created, restoredPreview.candidates.length);
      assert.equal((await store.importPreview(restoredPreview.fingerprint, actor, recollect)).unchanged, true);
      assert.equal((await db.query("SELECT count(*)::int n FROM customer_connector_drafts WHERE enabled OR review_state <> 'pending-review'")).rows[0].n, 0);
      console.log(JSON.stringify({ restoredCustomers: restoredPreview.companies.length, restoredDrafts: imported.created, destination: 'disposable-fixture-only' }));
      ok('restored source metadata imports and replays as disabled drafts in an isolated fixture database');
    } finally { await source.end(); }
  }
  console.log(JSON.stringify({ passed: checks, fixtureDatabaseRemovedOnExit: true, enabledBindings: 0 }));
} finally {
  await db?.end();
  if (created) await admin.query(`DROP DATABASE ${name}`);
  await admin.end();
}
