import assert from 'node:assert/strict';
import test from 'node:test';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
import {executiveHarness} from './executive-report-harness.mjs';
const {bundle}=await loadReportingSections(),h=await executiveHarness();
const company={id:'CO-A',name:'Fixture',industry:'Services'};
const policy={sla:{Critical:1,High:5,Medium:30,Low:90},catalog:h.threat.reportingKevCatalog()};
const transport=v=>JSON.parse(JSON.stringify(v));
function record(firstSeen){return {id:'F-1',companyId:company.id,connector:'defender',status:'Open',severity:'Critical',
 cve:'CVE-2021-44228',title:'Fixture',asset:'host',category:'Vulnerability',cvss:9.8,realRisk:80,kev:true,
 exploitAvailable:true,epss:0.5,firstSeen,lastSeen:firstSeen,assetExposure:'Internal',assetCriticality:'Normal'};}
test('bundle requires an explicit saved policy and catalog; no implicit bundled/live fallback',()=>{
 for(const p of [{},{...policy,sla:null},{...policy,catalog:null},{...policy,sla:{...policy.sla,High:NaN}},
  {...policy,catalog:{...policy.catalog,cves:['not-a-cve']}},
  {...policy,catalog:{...policy.catalog,cves:['CVE-2021-44228','CVE-2021-44228']}}])
  assert.throws(()=>bundle(company,{now:h.now,policy:p}),/catalog|policy/);
});
test('report uses one observation time with a maximum 15-minute lifetime, including SLA boundaries',()=>{
 const finding=record(new Date(h.now-86400000).toISOString());
 for(const offset of [0,1,15*60000]){
  const now=h.now+offset,acc=bundle(company,{now,policy});acc.finding(finding);
  const output=acc.finish([{ts:new Date(now).toISOString(),data:{totalOpen:1,severityCounts:{Critical:1}}}]);
  const expected=h.executive.buildExecutiveReport(company,[finding],[],[],{now,sla:policy.sla,isComplianceKev:h.threat.isKev});
  const {trend,...actual}=output.executive;assert.deepEqual(transport(actual),transport(expected));
  assert.equal(actual.sla.bySeverity.Critical.overdue,offset?1:0);
  assert.equal(output.validUntil,now+15*60000);assert.equal(trend[0].severityCounts.Critical,1);
 }
});
test('durable catalog restores across a process restart and rejects corrupt catalog data',async()=>{
 const initial=h.threat.reportingKevCatalog();
 const saved={...transport(initial),cves:[...initial.cves,'CVE-2099-99999'].sort(),ransomware:['CVE-2099-99999'],refreshedAt:new Date(h.now).toISOString()};
 const other=await executiveHarness();other.threat.restoreReportingKevCatalog(saved);
 assert.equal(other.threat.isKev('CVE-2099-99999'),true);assert.equal(other.threat.isKevRansomware('CVE-2099-99999'),true);
 assert.deepEqual(transport(other.threat.reportingKevCatalog()),saved);
 assert.throws(()=>other.threat.restoreReportingKevCatalog({...saved,ransomware:['CVE-2099-12345']}),/inconsistent/);
});
