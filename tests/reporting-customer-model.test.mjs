import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const cache = new Map();
async function load(path) {
  path = resolve(path);
  if (cache.has(path)) return cache.get(path);
  const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
  await mod.link(async name => load(resolve(dirname(path), `${name}.ts`)));
  return mod;
}
const module = await load('lib/reporting-customer-model.ts');
await module.evaluate();
const { buildCustomerReportingModel } = module.namespace;

const company = { id: 'CO-1', name: 'Openworks' };
const finding = (id, extra = {}) => ({ id, companyId: 'CO-1', connector: 'nessus', status: 'Open',
  severity: 'High', kev: false, exploitAvailable: false, cve: 'CVE-2026-1234', title: 'Patch',
  asset: `host-${id}`, assetSource: 'inferred', realRisk: 60, cvss: 8, lastSeen: '2026-09-27T10:00:00Z', ...extra });
const scan = (id, extra = {}) => ({ id, companyId: 'CO-1', connector: 'nessus', status: 'Completed',
  createdAt: '2026-09-27T09:00:00Z', completedAt: '2026-09-27T10:00:00Z', findingsCount: 0,
  name: 'Nessus assessment', ...extra });

test('empty customer is unassessed, not described as zero risk', () => {
  const model = buildCustomerReportingModel(company, [], [], [], []);
  assert.equal(model.metrics.vulnerabilities.open, 0);
  assert.equal(model.metrics.vulnerabilities.assessed, false);
  assert.equal(model.assessmentState, 'unassessed');
  assert.equal(model.history.length, 0);
  assert.equal(model.assets.inventoryCount, 0);
});

test('completed clean vulnerability scan is assessed while a failed scan is not', () => {
  const clean = buildCustomerReportingModel(company, [], [scan('ok')], [], []);
  const failed = buildCustomerReportingModel(company, [], [scan('bad', { status: 'Failed', completedAt: null })], [], []);
  assert.equal(clean.assessmentState, 'assessed');
  assert.equal(failed.assessmentState, 'unassessed');
  assert.equal(failed.sourceActivity[0].failedCount, 1);
});

test('large customer summaries stay bounded and reveal exact list totals', () => {
  const findings = Array.from({ length: 40 }, (_, index) => finding(String(index), { realRisk: index }));
  const scans = Array.from({ length: 20 }, (_, index) => scan(String(index)));
  const model = buildCustomerReportingModel(company, findings, scans, [], []);
  assert.equal(model.priorityTotal, 40);
  assert.equal(model.priorityRows.length, 25);
  assert.equal(model.priorityRows[0].id, '39');
  assert.equal(model.scanTotal, 20);
  assert.equal(model.recentScans.length, 12);
});

test('priority vulnerability list excludes OSINT and keeps web testing separate', () => {
  const model = buildCustomerReportingModel(company, [finding('v'), finding('o', { connector: 'spiderfoot' }),
    finding('w', { connector: 'zap' })], [], [], []);
  assert.equal(model.priorityTotal, 1);
  assert.deepEqual(model.priorityRows.map(row => row.id), ['v']);
  assert.deepEqual(model.attackSurfaceRows.map(row => row.id), ['o']);
  assert.deepEqual(model.webTestingRows.map(row => row.id), ['w']);
});

test('asset context and observed history do not imply scan coverage', () => {
  const model = buildCustomerReportingModel(company, [finding('v', { assetSource: 'tidal' })], [], [
    { companyId: 'CO-1', source: 'tidal', identifier: 'host-v', lastSynced: '2026-09-27T08:00:00Z' },
  ], [{ ts: '2026-09-26T00:00:00Z', data: { totalOpen: 3 } }]);
  assert.equal(model.assets.inventoryCount, 1);
  assert.equal(model.assets.authoritativeFindingCount, 1);
  assert.equal(model.assets.scanCoveragePercent, null);
  assert.deepEqual(model.history.map(point => [point.ts, point.open]), [['2026-09-26T00:00:00Z', 3]]);
});
