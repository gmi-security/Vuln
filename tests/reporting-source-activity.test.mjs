import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const path = resolve('lib/reporting-source-activity.ts');
const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const module = new SourceTextModule(code, { identifier: path });
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { buildSourceActivity, recordVulnersEnrichment } = module.namespace;

const finding = (connector, extra = {}) => ({ companyId: 'CO-1', connector, seenBy: [connector], status: 'Open', lastSeen: '2026-09-27T10:00:00Z', ...extra });
const scan = (connector, status = 'Completed') => ({ companyId: 'CO-1', connector, status,
  completedAt: status === 'Completed' ? '2026-09-27T10:00:00Z' : null, createdAt: '2026-09-27T09:00:00Z' });

test('one correlated finding is one customer finding but two source observations', () => {
  const rows = buildSourceActivity('CO-1', [scan('nessus'), scan('vulners')], [finding('nessus', { seenBy: ['nessus', 'vulners'] })], []);
  assert.deepEqual(rows.map(row => [row.source, row.openObservations, row.scanCount]), [
    ['nessus', 1, 1], ['vulners', 1, 1],
  ]);
});

test('Vulners cloud enrichment requires provenance and does not create a scan', () => {
  const without = buildSourceActivity('CO-1', [scan('nessus')], [finding('nessus')], []);
  assert.equal(without.some(row => row.source === 'vulners'), false);
  const withProvenance = buildSourceActivity('CO-1', [scan('nessus')], [finding('nessus', {
    enrichments: [{ source: 'vulners', observedAt: '2026-09-27T11:00:00Z' }],
  })], []);
  const vulners = withProvenance.find(row => row.source === 'vulners');
  assert.equal(vulners.scanCount, 0);
  assert.equal(vulners.evidence, 'enrichment');
  assert.equal(vulners.lastObservedAt, '2026-09-27T11:00:00Z');
});

test('asset-only source is visible without inventing findings or scans', () => {
  const rows = buildSourceActivity('CO-1', [], [], [
    { companyId: 'CO-1', source: 'intune', lastSynced: '2026-09-27T08:00:00Z' },
    { companyId: 'CO-2', source: 'tidal', lastSynced: '2026-09-27T08:00:00Z' },
  ]);
  assert.deepEqual(rows.map(row => [row.source, row.evidence, row.scanCount, row.openObservations]), [['intune', 'inventory', 0, 0]]);
});

test('running and failed scan states remain visible without a successful observation', () => {
  const rows = buildSourceActivity('CO-1', [scan('nessus', 'Running'), scan('nessus', 'Failed')], [], []);
  assert.equal(rows[0].completedCount, 0);
  assert.equal(rows[0].runningCount, 1);
  assert.equal(rows[0].failedCount, 1);
  assert.equal(rows[0].lastObservedAt, null);
});

test('Vulners provenance records the latest successful observation without duplication', () => {
  const prior = [{ source: 'vulners', observedAt: '2026-09-26T10:00:00Z' }];
  assert.deepEqual(recordVulnersEnrichment(prior, '2026-09-27T10:00:00Z'),
    [{ source: 'vulners', observedAt: '2026-09-27T10:00:00Z' }]);
  assert.deepEqual(recordVulnersEnrichment(prior, '2026-09-25T10:00:00Z'), prior);
});
