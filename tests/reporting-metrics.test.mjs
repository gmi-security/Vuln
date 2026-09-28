import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SourceTextModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const path = resolve('lib/reporting-metrics.ts');
const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const module = new SourceTextModule(code, { identifier: path });
await module.link(() => { throw new Error('Unexpected runtime import'); });
await module.evaluate();
const { buildReportingMetrics } = module.namespace;

const finding = (id, connector, status = 'Open', extra = {}) => ({
  id, companyId: 'CO-1', connector, status, severity: 'High', kev: false,
  exploitAvailable: false, overdue: false, seenBy: [connector], ...extra,
});
const scan = (id, connector, status = 'Completed') => ({
  id, companyId: 'CO-1', connector, status, completedAt: status === 'Completed' ? '2026-09-27T10:00:00Z' : null,
});

test('vulnerability and OSINT totals stay separate for a mixed customer', () => {
  const result = buildReportingMetrics('CO-1', [
    finding('v', 'nessus', 'Open', { severity: 'Critical', kev: true, seenBy: ['nessus', 'vulners'] }),
    finding('o', 'spiderfoot'),
    finding('w', 'burp'),
    finding('other', 'nessus', 'Open', { companyId: 'CO-2' }),
    finding('closed', 'nessus', 'Resolved'),
  ], [scan('s', 'nessus')]);
  assert.equal(result.vulnerabilities.open, 2);
  assert.equal(result.vulnerabilities.critical, 1);
  assert.equal(result.vulnerabilities.kev, 1);
  assert.equal(result.attackSurface.open, 1);
  assert.equal(result.webTesting.open, 1);
  assert.equal(result.vulnerabilities.bySeverity.Critical, 1);
});

test('assessment state distinguishes clean completed vulnerability scan from failed or OSINT scan', () => {
  assert.equal(buildReportingMetrics('CO-1', [], [scan('s', 'nessus')]).vulnerabilities.assessed, true);
  assert.equal(buildReportingMetrics('CO-1', [], [scan('s', 'nessus', 'Failed')]).vulnerabilities.assessed, false);
  assert.equal(buildReportingMetrics('CO-1', [], [scan('s', 'spiderfoot')]).vulnerabilities.assessed, false);
  assert.equal(buildReportingMetrics('CO-1', [finding('stored', 'nessus')], []).vulnerabilities.assessed, true);
});

test('ZAP is web testing and Nmap discovery is distinct from CVE vulnerability findings', () => {
  const result = buildReportingMetrics('CO-1', [
    finding('zap', 'zap', 'Open', { cve: 'ZAP-1001' }),
    finding('nmap', 'nmap', 'Open', { cve: 'NMAP-SERVICE-445' }),
  ], [scan('z', 'zap'), scan('n', 'nmap')]);
  assert.equal(result.vulnerabilities.open, 2);
  assert.equal(result.webTesting.open, 1);
  assert.equal(result.vulnerabilities.cveOpen, 0);
});
