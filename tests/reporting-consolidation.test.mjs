// node --experimental-vm-modules --test tests/reporting-consolidation.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const cache = new Map();
async function load(path) {
  path = resolve(path);
  if (cache.has(path)) return cache.get(path);
  const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const mod = new SourceTextModule(code, { identifier: path }); cache.set(path, mod);
  await mod.link(async name => {
    if (name.startsWith('.')) return load(resolve(dirname(path), `${name}.ts`));
    const values = await import(name);
    return new SyntheticModule(Object.keys(values), function() { for (const key of Object.keys(values)) this.setExport(key, values[key]); });
  });
  return mod;
}
const module = await load('lib/reporting-consolidation.ts');
await module.evaluate();
const { buildStoredFindingGroups } = module.namespace;
const company = { id: 'CO-147284', name: 'Atlas Healthcare' };
const finding = (id, source, cve = 'CVE-2026-1234', overrides = {}) => ({
  id, companyId: company.id, connector: source, cve, asset: `host-${id}`, status: 'Open',
  remediation: 'Upgrade Example Server to 3.2.1', severity: 'High', realRisk: 72, ...overrides,
});

test('corroborated findings share one review group while retaining source evidence', () => {
  const groups = buildStoredFindingGroups(company, [
    finding('one', 'nessus', undefined, { seenBy: ['nessus', 'vulners'] }),
    finding('two', 'crowdstrike'),
    finding('closed', 'nessus', undefined, { status: 'Resolved' }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].findingCount, 2);
  assert.deepEqual([...groups[0].connectors], ['crowdstrike', 'nessus', 'vulners']);
  assert.match(groups[0].csv, /host-one/);
  assert.doesNotMatch(groups[0].csv, /host-closed/);
});

test('identical generic remediation on different CVEs is kept separate', () => {
  const groups = buildStoredFindingGroups(company, [
    finding('one', 'nessus', 'CVE-2026-1234', { remediation: 'Apply vendor patch.' }),
    finding('two', 'vulners', 'CVE-2026-5678', { remediation: 'Apply vendor patch.' }),
  ]);
  assert.equal(groups.length, 2);
  assert.notEqual(groups[0].remediationId, groups[1].remediationId);
});

test('large action is split into reviewable batches without dropping findings', () => {
  const groups = buildStoredFindingGroups(company, Array.from({ length: 1001 }, (_, n) => finding(String(n).padStart(4, '0'), 'nessus')));
  assert.equal(groups.length, 2);
  assert.equal(groups.reduce((sum, group) => sum + group.findingCount, 0), 1001);
  assert.ok(groups.every(group => group.findingCount <= 1000));
});

test('already ticketed asset and CVE are excluded', () => {
  const excluded = new Set([JSON.stringify([company.id, 'host-one', 'CVE-2026-1234'])]);
  const groups = buildStoredFindingGroups(company, [finding('one', 'nessus'), finding('two', 'nessus')], excluded);
  assert.equal(groups[0].findingCount, 1);
});
