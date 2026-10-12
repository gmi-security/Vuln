import test from 'node:test';
import assert from 'node:assert/strict';
import {refreshModules,company,snapshot,storeFixture} from './defender-refresh-fixture.mjs';
const {store,assessment:{captureDefenderRefreshAssessment:capture},threat}=await refreshModules();
test('frozen assessment matches actual legacy scoring and ignores later threat/control mutations',()=>{
  const s=storeFixture();globalThis.__vulnStore=s;store.publishDefenderSnapshot(snapshot());const f=[...s.findings.values()][0],asset=[...s.assets.values()][0];
  const control={id:'C1',companyId:company.id,title:'Mitigation',effectivenessPct:25,status:'Active',cveMatch:f.cve,assetMatch:null};s.compensatingControls.set(control.id,control);
  const controls=[control],captured=capture(company.id,[f.cve],controls),expected=store.riskFields(s,{...f,inventory:asset});
  assert.deepEqual(captured.score(f,asset),expected);controls[0].effectivenessPct=99;captured.evidence.controls[0].effectivenessPct=100;
  threat.KEV_CVES.add(f.cve);
  try{assert.deepEqual(captured.score(f,asset),expected);assert.notEqual(capture(company.id,[f.cve],controls).digest,captured.digest);}
  finally{threat.KEV_CVES.delete(f.cve);}
});
test('frozen assessment refuses another customer, missing CVE evidence and invalid control scores',()=>{
  const s=storeFixture();globalThis.__vulnStore=s;store.publishDefenderSnapshot(snapshot());const f=[...s.findings.values()][0],asset=[...s.assets.values()][0],frozen=capture(company.id,[f.cve],[]);
  for(const [finding,inventory] of [[{...f,companyId:'CO-OTHER'},asset],[f,{...asset,companyId:'CO-OTHER'}],[{...f,cve:'CVE-2026-9999'},asset],[f,undefined]])assert.throws(()=>frozen.score(finding,inventory),/scope|snapshot/);
  assert.throws(()=>capture(company.id,[f.cve],[{companyId:company.id,effectivenessPct:101}]),/controls/);
});
