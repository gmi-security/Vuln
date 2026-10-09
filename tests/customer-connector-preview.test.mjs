import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConnectorPreview } from '../scripts/connector-preview-loader.mjs';
import { readApplicationConnectorMetadata } from '../lib/db/connector-metadata.mjs';

const build = await loadConnectorPreview();
const fixture = () => ({ companies: [{ id: 'CO-A', name: 'Alpha' }, { id: 'CO-B', name: 'Beta' },
  { id: 'CO-DEMO', name: 'Demo', isDemo: true }], defender: [], spotlight: [], connections: [], tiles: [] });
const falcon = { FALCON_CLIENT_ID: 'sentinel-client', FALCON_CLIENT_SECRET: 'sentinel-secret', FALCON_CUSTOMER: 'Alpha' };

test('explicit saved binding stays disabled and secrets never enter the preview', () => {
  const data = fixture();
  data.defender.push({ companyId: 'CO-A', tenantId: 'tenant-a', revision: 3, secret: 'SAVED_SECRET', clientId: 'SAVED_CLIENT' });
  const result = build(data, { ...falcon, MISP_URL: 'https://hidden.example', MISP_API_KEY: 'MISP_SECRET' });
  const saved = result.candidates.find(c => c.evidence === 'saved-binding');
  assert.equal(saved.companyId, 'CO-A'); assert.equal(saved.tenantId, 'tenant-a'); assert.equal(saved.revision, 3);
  for (const c of result.candidates) { assert.equal(c.enabled, false); assert.equal(c.state, 'pending-review'); assert.equal(c.authority, 'unassigned'); }
  for (const secret of ['sentinel-client', 'sentinel-secret', 'SAVED_SECRET', 'SAVED_CLIENT', 'MISP_SECRET', 'hidden.example'])
    assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(result.companies.length, 2);
});
test('Falcon name matching is evidence, not vendor tenant verification', () => {
  const result = build(fixture(), falcon).candidates[0];
  assert.equal(result.companyId, 'CO-A'); assert.equal(result.tenantId, null);
  assert.ok(result.review.includes('name-match-needs-review'));
  assert.ok(result.review.includes('vendor-tenant-not-verified'));
});
test('exact and near duplicate names never choose an arbitrary customer', () => {
  for (const name of ['ALPHA', 'Alpha Partners']) {
    const data = fixture(); data.companies.push({ id: 'CO-OTHER', name });
    const candidate = build(data, falcon).candidates[0]; assert.equal(candidate.companyId, null);
    assert.ok(candidate.review.some(r => r.includes('ambiguous') || r.includes('near-duplicate')));
  }
});
test('unknown and demo assignments are held for review', () => {
  const data = fixture(); data.defender.push({ companyId: 'CO-DEMO', tenantId: 'tenant', revision: 1 });
  assert.ok(build(data).candidates[0].review.includes('unknown-or-demo-customer'));
  assert.equal(build(fixture(), { ...falcon, FALCON_CUSTOMER: 'Unknown' }).candidates[0].companyId, null);
});
test('an unnamed base Falcon connection is never automatically assigned', () => {
  assert.equal(build(fixture(), { ...falcon, FALCON_CUSTOMER: '' }).candidates[0].companyId, null);
});
test('numbered Falcon gap and missing credentials are visible', () => {
  const env = { ...falcon, FALCON_CLIENT_ID_3: 'id3', FALCON_CLIENT_SECRET_3: 'secret3', FALCON_CUSTOMER_3: 'Beta' };
  const candidate = build(fixture(), env).candidates.find(c => c.connectionRef.endsWith('_3'));
  assert.ok(candidate.review.includes('legacy-loader-stops-before-this-entry'));
  const broken = build(fixture(), { FALCON_CLIENT_ID_2: 'id' }).candidates[0];
  assert.equal(broken.configured, false); assert.ok(broken.review.includes('incomplete-credentials'));
});
test('Falcon numbered configuration works without base and supports real cloud aliases', () => {
  const candidate = build(fixture(), { FALCON_CLIENT_ID_2: 'id', FALCON_CLIENT_SECRET_2: 'secret', FALCON_CUSTOMER_2: 'Beta', FALCON_CLOUD_2: 'US-2' }).candidates[0];
  assert.equal(candidate.companyId, 'CO-B'); assert.ok(!candidate.review.includes('unrecognized-cloud'));
  assert.ok(!candidate.review.includes('legacy-loader-stops-before-this-entry'));
});
test('Defender explicit IDs and conflicting saved tenant remain visible', () => {
  const data = fixture(); data.defender.push({ companyId: 'CO-A', tenantId: 'old', revision: 1 });
  const candidate = build(data, { DEFENDER_TENANT_ID: 'new', DEFENDER_CLIENT_ID: 'id', DEFENDER_CLIENT_SECRET: 'secret', DEFENDER_CUSTOMER: 'CO-A' })
    .candidates.find(c => c.evidence === 'environment-match');
  assert.equal(candidate.companyId, 'CO-A'); assert.ok(candidate.review.includes('saved-environment-tenant-conflict'));
});
test('same Defender tenant assigned to different customers is flagged', () => {
  const data = fixture(); data.defender.push({ companyId: 'CO-A', tenantId: 'shared', revision: 1 });
  const result = build(data, { DEFENDER_TENANT_ID: 'shared', DEFENDER_CLIENT_ID: 'id', DEFENDER_CLIENT_SECRET: 'secret', DEFENDER_CUSTOMER: 'CO-B' });
  assert.ok(result.candidates.every(c => c.review.includes('vendor-tenant-has-multiple-customers')));
});
test('saved tile ownership overrides legacy mapping including explicit null', () => {
  const data = fixture(); data.tiles.push({ id: 'tile1', source: 'elastic', companyId: null, revision: 1 },
    { id: 'tile2', source: 'crowdstrike', companyId: 'CO-B', revision: 1 }, { id: 'tile3', source: 'elastic', revision: 1 });
  const result = build(data, { REPORTING_CUSTOMER_TILE_IDS: JSON.stringify({ 'CO-A': ['tile1', 'tile2', 'tile3'] }) });
  const owner = id => result.candidates.find(c => c.tileId === id).companyId;
  assert.equal(owner('tile1'), null); assert.equal(owner('tile2'), 'CO-B'); assert.equal(owner('tile3'), 'CO-A');
  for (const c of result.candidates) { assert.equal(c.scope, 'unverified'); assert.ok(c.review.includes('tile-ownership-is-not-upstream-scope')); }
});
test('invalid legacy mappings abort instead of dropping assignments', () => {
  for (const value of ['bad-json', JSON.stringify({ 'CO-A': ['x'], 'CO-B': ['x'] })])
    assert.throws(() => build(fixture(), { REPORTING_CUSTOMER_TILE_IDS: value }));
});
test('Spotlight pointer is historical evidence with no tenant or connection permission', () => {
  const data = fixture(); data.spotlight.push({ companyId: 'CO-A', runId: 'generation', status: 'completed' });
  const candidate = build(data).candidates[0];
  assert.equal(candidate.connectionRef, null); assert.equal(candidate.tenantId, null);
  assert.equal(candidate.scope, 'historical-only'); assert.equal(candidate.capabilities.length, 0);
});
test('shared scanners and enrichment are never copied to every customer', () => {
  const result = build(fixture(), { SPIDERFOOT_URL: 'https://scanner', MISP_URL: 'https://misp', MISP_API_KEY: 'secret', INTUNE_TENANT_ID: 't', INTUNE_CLIENT_ID: 'id', INTUNE_CLIENT_SECRET: 'secret' });
  assert.equal(result.candidates.length, 3);
  assert.ok(result.candidates.every(c => c.companyId === null));
  assert.ok(result.candidates.find(c => c.provider === 'spiderfoot').review.includes('scan-to-customer-mapping-needs-review'));
});
test('preview is deterministic and revision changes its fingerprint, not logical identity', () => {
  const data = fixture(); data.defender.push({ companyId: 'CO-A', tenantId: 't', revision: 1 });
  const a = build(data, falcon); data.companies.reverse(); const b = build(data, falcon);
  assert.equal(a.fingerprint, b.fingerprint);
  data.defender[0].revision = 2; const c = build(data, falcon);
  assert.notEqual(c.fingerprint, a.fingerprint);
  assert.equal(c.candidates.find(x => x.evidence === 'saved-binding').id, a.candidates.find(x => x.evidence === 'saved-binding').id);
});
test('duplicate company IDs fail rather than suggesting ownership', () => {
  const data = fixture(); data.companies.push({ id: 'CO-A', name: 'Other' });
  assert.throws(() => build(data), /Duplicate company/);
});
test('database failures roll back without returning empty successful evidence', async () => {
  const queries = [];
  const client = { async query(sql) { queries.push(sql); if (sql.startsWith('SELECT')) throw new Error('fixture DB failure'); return { rows: [] }; } };
  await assert.rejects(() => readApplicationConnectorMetadata(client), /fixture DB failure/);
  assert.equal(queries[0], 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  assert.equal(queries.at(-1), 'ROLLBACK'); assert.ok(!queries.includes('COMMIT'));
});
