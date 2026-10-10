import {loadQueryRouting} from '../scripts/connector-preview-loader.mjs';
const queryRouting=await loadQueryRouting();
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';
import { loadConnectorPreview, loadConnectorStatus, loadInventoryRouting, loadSpotlightRouting, loadScannerRouting } from '../scripts/connector-preview-loader.mjs';
const build = await loadConnectorPreview(), project = await loadConnectorStatus(), inventory = await loadInventoryRouting(), spotlight = await loadSpotlightRouting(), scanner = await loadScannerRouting();
const metadata = () => ({ companies: [{ id: 'A', name: 'Alpha' }, { id: 'B', name: 'Beta' }],
  defender: [{ companyId: 'A', tenantId: 'PRIVATE_TENANT_A', revision: 1 }, { companyId: 'B', tenantId: 'PRIVATE_TENANT_B', revision: 1 }],
  spotlight: [], connections: [{ source: 'elastic', revision: 1 }], tiles: [{ id: 'tile-a', source: 'elastic', companyId: 'A', revision: 1 }] });
function draft(candidate, preview) {
  const sourceEvidence = candidate.evidence === 'saved-tile' ? preview.candidates.filter(c => c.evidence === 'shared-configuration' && c.connectionRef === candidate.connectionRef) : [];
  return { id: candidate.id, candidate, candidate_hash: createHash('sha256').update(JSON.stringify({ candidate, sourceEvidence })).digest('hex'),
    proposal: { companyId: candidate.companyId, tenantId: candidate.tenantId, datasets: ['PRIVATE_DATASET'], targets: ['PRIVATE_HOST'], authority: 'query-only' },
    source_present: true, review_state: 'reviewed', reviewed_at: '2026-10-09T00:00:00Z' };
}
test('only selected customer evidence is exposed; raw tenants, scopes and connection references stay private', () => {
  const preview = build(metadata(), { MISP_URL: 'https://private', MISP_API_KEY: 'KEY' });
  const drafts = preview.candidates.filter(c => c.companyId).map(c => draft(c, preview));
  const result = project('A', preview, drafts, true);
  assert.equal(result.items.length, 2);
  assert.ok(result.items.every(c => c.review === 'Reviewed · inactive'));
  for (const hidden of ['PRIVATE_', 'defender_connections', 'MISP', 'Beta', 'companyId":"B']) assert.ok(!JSON.stringify(result).includes(hidden));
  assert.equal(project('B', preview, drafts, true).items.length, 1);
});
test('missing registry is distinct from empty customer evidence and never enables proposals', () => {
  const preview = build(metadata()); const result = project('A', preview, [], false);
  assert.equal(result.registryAvailable, false); assert.equal(result.items[0].review, 'Not imported for review');
  const empty = { ...preview, companies: [...preview.companies, { id: 'EMPTY', name: 'Empty' }] };
  assert.equal(project('EMPTY', empty, [], true).items.length, 0);
  assert.throws(() => project('', preview, [], true), /Customer not found/);
});
test('current source and shared connection changes invalidate review without a database write', () => {
  const data = metadata(), preview = build(data);
  const saved = preview.candidates.filter(c => c.companyId === 'A').map(c => draft(c, preview));
  data.defender[0].revision++; data.connections[0].revision++;
  const result = project('A', build(data), saved, true);
  assert.ok(result.items.every(c => c.review === 'Needs review'));
  assert.ok(saved.every(c => c.review_state === 'reviewed'));
});
test('changed tile ownership never exposes the new owner or tenant through a previous proposal', () => {
  const data = metadata(), preview = build(data); const tile = preview.candidates.find(c => c.tileId);
  const saved = draft(tile, preview); data.tiles[0].companyId = 'B';
  const result = project('A', build(data), [saved], true).items.find(c => c.id === tile.id);
  assert.equal(result.configuration, 'Assignment changed'); assert.equal(result.review, 'Needs review');
  assert.ok(!JSON.stringify(result).includes('PRIVATE_'));
  assert.ok(!JSON.stringify(result).includes('Beta'));
});
test('missing source retains a warning; unassigned shared connections appear only with a customer proposal', () => {
  const data = metadata(), preview = build(data, { SPIDERFOOT_URL: 'https://hidden' });
  const saved = draft(preview.candidates.find(c => c.provider === 'spiderfoot'), preview); saved.proposal.companyId = 'A';
  assert.equal(project('A', preview, [saved], true).items.find(c => c.provider === 'spiderfoot').configuration, 'Proposed assignment');
  assert.ok(!project('B', preview, [saved], true).items.some(c => c.provider === 'spiderfoot'));
  const result = project('A', build(data), [saved], true).items.find(c => c.provider === 'spiderfoot');
  assert.equal(result.configuration, 'No longer recorded'); assert.equal(result.review, 'Needs review');
});

async function load(file, stubs) {
  const code = ts.transpileModule(await readFile(file, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const mod = new SourceTextModule(code);
  await mod.link(name => {
    assert.ok(stubs[name], `Unexpected dependency ${name}`);
    const values = stubs[name]; return new SyntheticModule(Object.keys(values), function () { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  }); await mod.evaluate(); return mod.namespace;
}
class DashboardError extends Error { constructor(message, status) { super(message); this.status = status; } }
test('status GET requires current access, rollout flag and explicit customer; setup returns only a list and no mutation method exists', async () => {
  let enabled = true, accessError = false; const calls = [];
  const route = await load('app/api/elastic-dashboard/customer-connectors/route.ts', {
    '@/lib/elastic-dashboard-http': { dashboardAccess: async () => { if (accessError) throw new DashboardError('Unauthorized', 401); },
      dashboardJson: value => ({ status: 200, value }), dashboardFailure: error => ({ status: error.status ?? 503 }) },
    '@/lib/elastic-dashboard': { DashboardError }, '@/lib/remediation-server': { remediationUiEnabled: () => enabled },
    '@/lib/customer-connector-status-service': { readCustomerConnectorStatus: async id => { calls.push(id); return id === null ? { companies: [] } : { companyId: id }; } },
  });
  const get = params => route.GET(new Request('http://localhost/api/elastic-dashboard/customer-connectors'+params));
  for (const params of ['', '?companyId=', '?setup=1&companyId=']) assert.equal((await get(params)).status, 400);
  assert.deepEqual(calls, []);
  assert.equal((await get('?setup=1')).status, 200); assert.deepEqual(calls, [null]);
  assert.equal((await get('?companyId=A')).value.companyId, 'A');
  enabled = false; assert.equal((await get('?companyId=A')).status, 404);
  enabled = true; accessError = true; assert.equal((await get('?companyId=A')).status, 401);
  assert.deepEqual(calls, [null, 'A']); assert.equal(route.POST, undefined); assert.equal(route.DELETE, undefined);
});
test('page keeps original tools with flag off and scopes the new navigation without granting configuration access', async () => {
  let enabled = false, denied = false; const calls = [];
  const page = await load('app/connectors/page.tsx', {
    '@/components/VulnConnectorsPage': { default: 'Legacy' }, '@/components/CustomerConnectorsPage': { default: 'Customer' },
    '@/lib/remediation-server': { remediationUiEnabled: () => enabled }, '@/lib/elastic-vuln-server': { elasticVulnEnabled: () => true },
    '@/lib/elastic-dashboard-http': { dashboardAccess: async () => { calls.push('access'); if (denied) throw new DashboardError('Unauthorized', 401); } },
    '@/lib/elastic-dashboard': { DashboardError }, 'next/navigation': { redirect: url => { throw new Error(`redirect:${url}`); } },
    '@/lib/remediation-view': { customerConnectorsHref: id => `/connectors?companyId=${id}` },
    'react/jsx-runtime': { jsx: (type, props) => ({ type, props }) },
  });
  const render = query => page.default({ searchParams: Promise.resolve(query) });
  assert.equal((await render({})).type, 'Legacy'); assert.equal(calls.length, 0);
  enabled = true; assert.equal((await render({ companyId: 'A' })).props.initialCompanyId, 'A');
  assert.equal((await render({ companyId: 'A', view: 'shared' })).props.customerHref, '/connectors?companyId=A');
  denied = true; await assert.rejects(() => render({}), /redirect:\/login/);
});
test('read service skips schema initialization, preserves customer filters and fails rather than reporting query errors as empty', async () => {
  const data = metadata(), statements = []; let available = false, fail = false;
  const client = { release() { statements.push('release'); }, async query(sql, values) {
    statements.push(sql); if (sql.includes('to_regclass')) return { rows: [{ name: available ? 'customer_connector_drafts' : null }] };
    if (sql.includes('FROM public.customer_connector_drafts')) { assert.deepEqual(values, ['A']); if (fail) throw new Error('fixture failure'); return { rows: [] }; }
    return { rows: [] };
  } };
  const app = { connect: async () => client };
  const old = process.env.ELASTIC_VULN_DATABASE_URL; delete process.env.ELASTIC_VULN_DATABASE_URL;
  try {
    const service = await load('lib/customer-connector-status-service.ts', {
      'pg': { Pool: class { constructor() { throw new Error('Unexpected new database'); } } },
      './persist': { applicationDatabase: () => app }, './elastic-dashboard': { DashboardError },
      './customer-query-routing':queryRouting, './customer-scanner-routing':scanner, './customer-spotlight-routing':spotlight, './customer-inventory-routing': inventory, './customer-connector-preview': { buildConnectorPreview: build }, './customer-connector-status': { customerConnectorStatus: project },
      './db/connector-metadata.mjs': { readApplicationConnectorMetadata: async () => data, readDashboardConnectorMetadata: async () => data },
    });
    assert.equal((await service.readCustomerConnectorStatus('A')).registryAvailable, false);
    assert.deepEqual(Object.keys(await service.readCustomerConnectorStatus(null)), ['companies']);
    await assert.rejects(() => service.readCustomerConnectorStatus('OTHER'), error => error.status === 404);
    await assert.rejects(() => service.readCustomerConnectorStatus(''), error => error.status === 400);
    available = true; fail = true; await assert.rejects(() => service.readCustomerConnectorStatus('A'), /fixture failure/);
    assert.ok(statements.includes('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')); assert.ok(statements.includes('ROLLBACK'));
    assert.ok(statements.every(sql => !/^(INSERT|UPDATE|DELETE|CREATE|ALTER)/.test(sql)));
  } finally { if (old === undefined) delete process.env.ELASTIC_VULN_DATABASE_URL; else process.env.ELASTIC_VULN_DATABASE_URL = old; }
});

test('status reads each customer binding over the legacy proposal without exporting private scope', async () => {
  const data=metadata(),preview=build(data),source=preview.candidates.find(c=>c.evidence==='shared-configuration');
  const legacy=draft(source,preview);legacy.proposal.companyId='A';
  const queries=[];
  const client={release(){},async query(sql,params){
    queries.push(sql);
    if(sql.includes('to_regclass'))return {rows:[{name:'present'}]};
    if(sql.includes('FROM public.customer_connector_bindings')){
      assert.ok(['A','B'].includes(params[0]));assert.match(sql,/WHERE b.company_id=\$1/);
      const row=draft(source,preview);row.proposal.companyId=params[0];
      row.proposal.targets=params[0]==='A'?['PRIVATE_ALPHA']:['PRIVATE_BETA'];
      row.review_state=params[0]==='A'?'dismissed':'reviewed';return {rows:[row]};
    }
    if(sql.includes('FROM public.customer_connector_drafts'))return {rows:params[0]==='A'?[legacy]:[]};
    return {rows:[]};
  }};
  const old=process.env.ELASTIC_VULN_DATABASE_URL;delete process.env.ELASTIC_VULN_DATABASE_URL;
  try {
    const service=await load('lib/customer-connector-status-service.ts',{
      'pg':{Pool:class{constructor(){throw Error('Unexpected pool');}}},
      './persist':{applicationDatabase:()=>({connect:async()=>client})},'./elastic-dashboard':{DashboardError},
      './customer-query-routing':queryRouting, './customer-scanner-routing':scanner, './customer-spotlight-routing':spotlight, './customer-inventory-routing':inventory, './customer-connector-preview':{buildConnectorPreview:build},'./customer-connector-status':{customerConnectorStatus:project},
      './db/connector-metadata.mjs':{readApplicationConnectorMetadata:async()=>data,readDashboardConnectorMetadata:async()=>data},
    });
    const a=await service.readCustomerConnectorStatus('A'),b=await service.readCustomerConnectorStatus('B');
    assert.match(a.items.find(i=>i.id===source.id).review,/Dismissed/);
    assert.match(b.items.find(i=>i.id===source.id).review,/Reviewed/);
    assert.doesNotMatch(JSON.stringify([a,b]),/PRIVATE_|dashboard:/);
    assert.ok(queries.every(sql=>!/^(INSERT|UPDATE|DELETE|CREATE|ALTER)/.test(sql)));
  }finally{if(old===undefined)delete process.env.ELASTIC_VULN_DATABASE_URL;else process.env.ELASTIC_VULN_DATABASE_URL=old;}
});
