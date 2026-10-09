// Real legacy transformation/metrics functions, synthetic observations only.
// Does not import the store singleton, initialize a database or score live findings.
import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import * as crypto from 'node:crypto';
import ts from 'typescript';
const cache=new Map();
for(const name of ['defender-projection','finding-correlation','reporting-metrics']){
  const code=ts.transpileModule(await readFile(`lib/${name}.ts`,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  cache.set(name,new SourceTextModule(code));
}
const builtin=new SyntheticModule(Object.keys(crypto),function(){for(const k of Object.keys(crypto))this.setExport(k,crypto[k]);});
const linker=specifier=>{
  if(specifier==='node:crypto')return builtin;
  const mod=cache.get(specifier.replace('./',''));assert.ok(mod,`No store or runtime dependency permitted: ${specifier}`);return mod;
};
for(const mod of cache.values()){if(mod.status==='unlinked')await mod.link(linker);if(mod.status==='linked')await mod.evaluate();}
const {planDefenderProjection:project}=cache.get('defender-projection').namespace;
const {buildReportingMetrics:metrics}=cache.get('reporting-metrics').namespace;
const when='2026-10-09T12:00:00Z';
const device={deviceId:'d1',hostname:'host1',ip:'10.0.0.1',os:'Windows',lastSeen:when};
const row={deviceId:'d1',hostname:'host1',cve:'CVE-2026-12345',severity:'HIGH',cvss:8.1,firstSeen:when,lastSeen:when,remediation:'Install update',exploitAvailable:false};
const snapshot=extra=>({companyId:'CO-A',runId:'run1',observedAt:when,devices:[device],findings:[row],...extra});
const plan=(snap,findings=[],assets=[])=>project(snap,'Fixture',findings,assets,()=>({realRisk:42,riskPriority:'High'}));
const first=()=>plan(snapshot());
const one=p=>[...p.findings.values()][0];
const assets=p=>[...p.assets.values()];
test('zero findings in a new source import can coexist with an open platform finding for an offline device',()=>{
  const previous=first(),finding=one(previous);
  const next=plan(snapshot({runId:'run2',devices:[],findings:[]}),[finding],assets(previous));
  assert.equal(next.findings.size,0); // No update; the prior platform record remains.
  assert.equal(metrics('CO-A',[finding],[]).vulnerabilities.open,1);
  assert.equal(snapshot({findings:[]}).findings.length,0);
});
test('source evidence may still be present while an accepted platform finding is not in open totals',()=>{
  const previous=first(),accepted={...one(previous),status:'Risk Accepted',assignee:'analyst'};
  const published=one(plan(snapshot({runId:'run2'}),[accepted],assets(previous)));
  assert.equal(published.status,'Risk Accepted');assert.equal(published.assignee,'analyst');
  assert.equal(metrics('CO-A',[published],[]).vulnerabilities.open,0);assert.equal(snapshot().findings.length,1);
});
test('corroborating legacy source severity survives a weaker Defender assessment',()=>{
  const previous=first(),old=one(previous);delete old.defender;
  Object.assign(old,{connector:'nessus',seenBy:['nessus'],severity:'Critical',cvss:9.8,cvssV3:9.8,asset:'host1'});
  const published=one(plan(snapshot({findings:[{...row,severity:'LOW',cvss:3}]}),[old],[]));
  assert.equal(published.id,old.id);assert.equal(published.severity,'Critical');assert.equal(published.cvss,9.8);
  assert.deepEqual(new Set(published.seenBy),new Set(['nessus','defender']));
  assert.equal(metrics('CO-A',[published],[]).vulnerabilities.critical,1);
});
test('Defender absence cannot resolve evidence retained by another scanner',()=>{
  const previous=first(),old={...one(previous),seenBy:['defender','nessus']};
  const published=one(plan(snapshot({runId:'run2',observedAt:'2026-10-10T12:00:00Z',devices:[{...device,lastSeen:'2026-10-10T11:00:00Z'}],findings:[]}),[old],assets(previous)));
  assert.equal(published.defender.active,false);assert.equal(published.status,'Open');assert.deepEqual(published.seenBy,['nessus']);
  assert.equal(metrics('CO-A',[published],[]).vulnerabilities.open,1);
});
test('current reporting remediation totals include web findings but exclude OSINT',()=>{
  const base=one(first());
  const result=metrics('CO-A',[base,{...base,id:'web',connector:'burp',cve:'WEB-test'},
    {...base,id:'osint',connector:'spiderfoot',cve:'OSINT-test'}, {...base,id:'foreign',companyId:'CO-B'}],[]);
  assert.equal(result.vulnerabilities.open,2);assert.equal(result.vulnerabilities.cveOpen,1);
  assert.equal(result.webTesting.open,1);assert.equal(result.attackSurface.open,1);
});
test('shared hostname and IP are not sufficient to collapse two Defender device identities',()=>{
  const result=plan(snapshot({devices:[device,{...device,deviceId:'d2'}],findings:[row,{...row,deviceId:'d2'}]}));
  assert.equal(result.findings.size,2);assert.equal(result.assets.size,2);
  assert.equal(metrics('CO-A',[...result.findings.values()],[]).vulnerabilities.open,2);
});
