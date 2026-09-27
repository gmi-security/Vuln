// node --experimental-vm-modules --test tests/reporting-insights.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const path = resolve('lib/reporting-insights.ts');
const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const module = new SourceTextModule(code, { identifier: path });
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { buildCustomerInsights } = module.namespace;

test('customer views exclude other companies and resolved findings while preserving source evidence', () => {
  const findings = [
    { id: 'a', companyId: 'CO-1', status: 'Open', severity: 'Critical', realRisk: 90, cvss: 9,
      connector: 'nessus', seenBy: ['nessus', 'vulners'], cve: 'CVE-2026-1234', title: 'Example', asset: 'host-a' },
    { id: 'b', companyId: 'CO-1', status: 'Resolved', severity: 'High', realRisk: 50, cvss: 8, connector: 'nessus' },
    { id: 'c', companyId: 'CO-2', status: 'Open', severity: 'Critical', realRisk: 100, cvss: 10, connector: 'crowdstrike' },
  ];
  const scans = [
    { id: 'scan-a', companyId: 'CO-1', connector: 'nessus', createdAt: '2026-09-25' },
    { id: 'scan-c', companyId: 'CO-2', connector: 'crowdstrike', createdAt: '2026-09-26' },
  ];
  const result = buildCustomerInsights('CO-1', findings, scans);
  assert.equal(result.totalOpen, 1);
  assert.equal(result.totalScans, 1);
  assert.deepEqual(result.sources.map(row => [row.name, row.open, row.scans]), [['nessus', 1, 1], ['vulners', 1, 0]]);
  assert.deepEqual(result.highestRisk.map(row => row.id), ['a']);
  assert.deepEqual(result.recentScans.map(row => row.id), ['scan-a']);
});

test('totals include every customer finding even when the table shows only the highest risk rows', () => {
  const findings = Array.from({ length: 80 }, (_, index) => ({ id: String(index), companyId: 'CO-1',
    status: 'Open', severity: 'High', realRisk: index, cvss: 8, connector: 'vulners' }));
  const result = buildCustomerInsights('CO-1', findings, []);
  assert.equal(result.totalOpen, 80);
  assert.equal(result.severity.find(row => row.name === 'High').count, 80);
  assert.equal(result.highestRisk.length, 25);
  assert.equal(result.highestRisk[0].id, '79');
});
