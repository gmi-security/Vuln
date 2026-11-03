// node --experimental-vm-modules --test tests/external-scan-plan.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import {readFile} from 'node:fs/promises';
import {SourceTextModule, SyntheticModule} from 'node:vm';

const src = await readFile('lib/external-scan-plan.ts','utf8');
const js = ts.transpileModule(src,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const keys = value => {
  if (value.includes('/') || value.includes('*') || value.includes('://') || !value) throw new Error('Invalid target');
  return value.toLowerCase().replace(/\.$/,'');
};
const module = new SourceTextModule(js);
await module.link(async name => {
  assert.equal(name,'./scanner-target-scope');
  return new SyntheticModule(['scannerExactTargetKey'],function(){this.setExport('scannerExactTargetKey',keys);});
});
await module.evaluate();
const {buildExternalScanPlan} = module.namespace;
const matrix = (scans=[{nessusScanId:11,scanName:'Nessus A',enabled:true,
  nextOccurrence:'2026-11-04T01:00:00Z',offsetNextTrigger:'2026-11-04T02:00:00Z'}])=>({
  generatedAt:'2026-11-03T20:00:00Z',
  companies:[{companyId:'CO-A',companyName:'Customer A',scans}],
});
const routes = (targets=['alpha.example'])=>[{companyId:'CO-A',provider:'vulners',targets}];

test('no reviewed routes => no scan candidates, no legacy fallback',()=>{
  const p=buildExternalScanPlan(matrix(),null);
  assert.equal(p.launchesEnabled,false);assert.equal(p.candidates.length,0);
  assert.equal(p.routeStatus,'unavailable');
});
test('unique approved host produces preview only, never executable',()=>{
  const p=buildExternalScanPlan(matrix(),routes());
  assert.equal(p.mode,'preview-only');assert.equal(p.launchesEnabled,false);
  assert.equal(p.candidates.length,1);
  assert.equal(p.candidates[0].state,'review-required');
  assert.equal(p.candidates[0].nominalOffsetAt,'2026-11-04T02:00:00Z');
});
test('disabled Nessus schedules do not queue scans',()=>{
  const p=buildExternalScanPlan(matrix([{nessusScanId:11,scanName:'Disabled',enabled:false,
    nextOccurrence:'2026-11-04T01:00:00Z',offsetNextTrigger:'2026-11-04T02:00:00Z'}]),routes());
  assert.equal(p.candidates.length,0);
});
test('same host and multiple Nessus schedules generate one candidate',()=>{
  const m=matrix();m.companies[0].scans.push({nessusScanId:12,scanName:'Nessus B',enabled:true,
    nextOccurrence:'2026-11-04T03:00:00Z',offsetNextTrigger:'2026-11-04T04:00:00Z'});
  const p=buildExternalScanPlan(m,routes(['ALPHA.example','alpha.example']));
  assert.equal(p.candidates.length,1);assert.equal(p.candidates[0].nessusScanId,11);
});
test('CIDR, wildcard and wrong offset are rejected',()=>{
  for(const value of ['10.0.0.0/24','*.example'])assert.equal(buildExternalScanPlan(matrix(),routes([value])).candidates.length,0);
  const p=buildExternalScanPlan(matrix([{nessusScanId:11,scanName:'Bad offset',enabled:true,
    nextOccurrence:'2026-11-04T01:00:00Z',offsetNextTrigger:'2026-11-04T01:00:00Z'}]),routes());
  assert.equal(p.candidates.length,0);
});
test('cross-company route overlap blocks both customers',()=>{
  const m=matrix();m.companies.push({companyId:'CO-B',companyName:'Customer B',scans:m.companies[0].scans});
  const r=[...routes(),{companyId:'CO-B',provider:'vulners',targets:['ALPHA.example']}];
  const p=buildExternalScanPlan(m,r);
  assert.equal(p.candidates.length,0);
  assert.equal(p.blocked.length,2);
});
test('missing approval blocks scheduling even if Nessus has imported scans',()=>{
  const p=buildExternalScanPlan(matrix(),[]);
  assert.equal(p.candidates.length,0);
  assert.match(p.blocked[0].reason,/No approved/);
});
