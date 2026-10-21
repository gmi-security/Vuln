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
  assert.deepEqual(groups[0].reviewRows.map(row => [row.asset, row.cve, row.severity, row.risk, row.connectors]), [
    ['host-one', 'CVE-2026-1234', 'High', 72, ['nessus', 'vulners']],
    ['host-two', 'CVE-2026-1234', 'High', 72, ['crowdstrike']],
  ]);
  assert.doesNotMatch(groups[0].csv, /host-closed/);
});

test('new drafts for both approved canonical customers require manual review', () => {
  for (const id of ['CO-229336', 'CO-229438']) {
    const selected = { id, name: 'Approved destination' };
    const groups = buildStoredFindingGroups(selected, [finding('one', 'nessus', undefined, { companyId: id })]);
    assert.equal(groups.length, 1);
    assert.equal(groups[0].manualOnly, true);
  }
  assert.equal(buildStoredFindingGroups(company, [finding('one', 'nessus')])[0].manualOnly, undefined);
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

test('maxRisk is the highest realRisk among the group\'s findings, not an average or the first row\'s', () => {
  const groups = buildStoredFindingGroups(company, [
    finding('one', 'nessus', undefined, { realRisk: 35 }),
    finding('two', 'vulners', undefined, { realRisk: 91 }),
    finding('three', 'crowdstrike', undefined, { realRisk: 60 }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].maxRisk, 91);
});

test('maxRisk is 0 for an empty group rather than -Infinity', () => {
  const groups = buildStoredFindingGroups(company, [finding('one', 'nessus', undefined, { realRisk: 0 })]);
  assert.equal(groups[0].maxRisk, 0);
});

test('automatic patch drafts exclude OSINT and non-CVE service findings', () => {
  const groups = buildStoredFindingGroups(company, [
    finding('v', 'nessus'),
    finding('o', 'spiderfoot'),
    finding('n', 'nmap', 'NMAP-SERVICE-445'),
    finding('z', 'zap', 'ZAP-1001'),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].findingCount, 1);
  assert.deepEqual(groups[0].connectors, ['nessus']);
});

const defenderUpdate = (overrides = {}) => ({ softwareVendor: 'microsoft', softwareName: 'windows_11', softwareVersion: '10.0.26200.9448', remediation: 'October 2026 Security Updates', remediationId: '5127648', ...overrides });
const defenderFinding = (id, overrides = {}) => finding(id, 'defender', 'CVE-2026-100202', {
  remediation: `windows_11 ? installed-build-${id} ? October 2026 Security Updates ? 5127648`,
  defender: { active: true, deviceId: id, runId: 'published-run', hostname: `host-${id}` }, ...overrides,
});

test('Defender installed builds consolidate into five product/update drafts with all 505 devices', () => {
  const counts = [['windows_11','5127648',494],['windows_server_2022','5126655',6],['windows_server_2025','5126646',2],['windows_10','5126657',2],['windows_11','5126653',1]];
  const findings = [], updates = new Map();
  for (const [product, update, count] of counts) for (let n = 0; n < count; n++) {
    const id = `${product}-${update}-${n}`;
    findings.push(defenderFinding(id));
    updates.set(id, [defenderUpdate({ softwareName: product, remediationId: update, softwareVersion: `build-${n % 27}` })]);
  }
  const groups = buildStoredFindingGroups(company, findings, new Set(), updates);
  assert.equal(groups.length, 5);
  assert.deepEqual(groups.map(g => g.deviceCount).sort((a,b)=>b-a), [494,6,2,2,1]);
  assert.equal(new Set(groups.flatMap(g => g.hostScope)).size, 505);
  assert.equal(groups.reduce((sum,g)=>sum+g.findingCount,0), 505);
  const largest = groups.find(g=>g.deviceCount===494);
  assert.equal(largest.title, 'Windows 11 — Install KB5127648');
  assert.equal(largest.reference, 'KB5127648');
  assert.match(largest.csv, /installed_versions/);
  assert.match(largest.csv, /build-26/);
  assert.doesNotMatch(largest.ticketBody, /host-windows|build-26/);
  assert.match(largest.ticketBody, /Windows 11/);
});

test('Defender keeps multiple installed versions in one host row but separates different recommended updates', () => {
  const item = defenderFinding('one');
  const updates = new Map([['one',[defenderUpdate(), defenderUpdate({softwareVersion:'10.0.26200.9457'}), defenderUpdate({remediationId:'5126653'})]]]);
  const groups = buildStoredFindingGroups(company, [item], new Set(), updates);
  assert.equal(groups.length, 2);
  assert.ok(groups.every(g=>g.deviceCount===1 && g.deviceCves.length===1 && g.findingCount===1));
  const first=groups.find(g=>g.reference==='KB5127648');
  assert.match(first.csv, /10.0.26200.9448; 10.0.26200.9457/);
  assert.equal(first.csv.trim().split('\n').length, 2);
  const newer = buildStoredFindingGroups(company,[item],new Set(),new Map([['one',[defenderUpdate({softwareVersion:'newer-installed-build'})]]]));
  assert.equal(newer[0].remediationId, first.remediationId);
  const changedAction = buildStoredFindingGroups(company,[item],new Set(),new Map([['one',[defenderUpdate({remediation:'Different update instructions'})]]]));
  assert.notEqual(changedAction[0].remediationId, first.remediationId);
});

test('Defender identity retains customer, CVE, vendor and product boundaries and active-ticket exclusions', () => {
  const one=defenderFinding('one'), other=defenderFinding('other',{cve:'CVE-2026-100203'});
  const evidence=new Map([['one',[defenderUpdate(),defenderUpdate({softwareName:'windows_10'}),defenderUpdate({softwareVendor:'another-vendor'})]],['other',[defenderUpdate()]]]);
  const groups=buildStoredFindingGroups(company,[one,other,defenderFinding('foreign',{companyId:'CO-B'})],new Set(),evidence);
  assert.equal(groups.length,4);
  const moved=buildStoredFindingGroups({id:'CO-B',name:'B'},[{...one,companyId:'CO-B'}],new Set(),evidence);
  assert.ok(moved.every(m=>groups.every(g=>m.remediationId!==g.remediationId)));
  const excluded=new Set([JSON.stringify([company.id,one.asset,one.cve])]);
  assert.equal(buildStoredFindingGroups(company,[one,other],excluded,evidence).length,1);
});

test('incomplete Defender evidence and corroborating scanner actions retain conservative exact-action grouping', () => {
  const one=defenderFinding('one'), two=defenderFinding('two');
  for (const updates of [new Map(),new Map([['one',[defenderUpdate(),defenderUpdate({remediationId:''})]],['two',[defenderUpdate({softwareName:''})]]])]) {
    assert.equal(buildStoredFindingGroups(company,[one,two],new Set(),updates).length,2);
  }
  const mixed=defenderFinding('mixed',{seenBy:['defender','nessus'],remediation:'Install another scanner fix; Defender update',defender:{...one.defender,otherRemediation:'Install another scanner fix'}});
  const [group]=buildStoredFindingGroups(company,[mixed],new Set(),new Map([['mixed',[defenderUpdate()]]]));
  assert.match(group.ticketBody,/another scanner fix/);
  assert.equal(group.title, `${mixed.cve} remediation`);
});
