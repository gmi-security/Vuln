import assert from 'node:assert/strict';
import test from 'node:test';
import {executiveHarness} from './executive-report-harness.mjs';
import {reportingFixture,company as baseCompany} from './reporting-sections-fixture.mjs';
const h=await executiveHarness(),day=86400000,company={...baseCompany,industry:'Fixture industry',contactEmail:'private@example.invalid'};
const sla={Critical:1,High:5,Medium:20,Low:40};
const iso=d=>new Date(h.now-d*day).toISOString(),transport=x=>JSON.parse(JSON.stringify(x));
function data(n=500){
 const d=reportingFixture(n);
 d.findings=d.findings.map((r,i)=>({...r,cvssV2:i%5,cvssV3:i%10,epss:i%100/100,riskPriority:r.severity,ransomware:i%19===0,
  firstSeen:iso(i%200),resolvedAt:r.status==='Resolved'?iso(i%100):null,category:['SpiderFoot: password','Artemis: nuclei','SpiderFoot: dns'][i%3],
  assetExposure:['Internet-facing','Internal','Isolated'][i%3],assetCriticality:['Crown Jewel','High','Normal','Low'][i%4]}));
 d.scans=d.scans.map(r=>({...r,vendor:{lastPoll:h.now},progressFrozenAt:0}));
 d.assets=d.assets.map((r,i)=>({...r,hostname:i%2?r.identifier.toUpperCase():'other',ipAddresses:[`host-${i%30}`]}));
 return d;
}
function state(d,policy=sla){return {companies:new Map([[company.id,company]]),findings:new Map(d.findings.map(f=>[f.id,f])),
 scans:new Map(d.scans.map(f=>[f.id,f])),assets:new Map(d.assets.map(f=>[f.id,f])),folders:new Map(),identityAliases:new Map(),compensatingControls:new Map(),
 settings:{sla:policy,autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false}},meta:{},seeded:true,counter:1000};}
function compare(d,policy=sla){
 const s=state(d,policy);h.setState(s);
 const expected=h.legacy.legacyExecutiveReport(h.store,s,company.id);
 const actual=h.executive.buildExecutiveReport(company,s.findings.values(),s.scans.values(),s.assets.values(),{now:h.now,sla:policy,isComplianceKev:h.threat.isKev});
 assert.deepEqual(transport(actual),transport(expected));assert.deepEqual(transport(h.store.computeExecReport(company.id)),transport(expected));
 assert.deepEqual(Object.keys(actual.company).sort(),['id','industry','name']);return actual;
}
test('all finding providers, workflow states and inventory match every legacy executive field',()=>{compare(data(1250));});
test('single-pass report preserves full counts and ranking beyond the old 5000-row priority limit',()=>{const report=compare(data(20000));assert.equal(report.topRisks.length,5);assert.ok(report.findings.open>5000);});
test('customer isolation includes findings, scans and inventory',()=>{
 const d=data(),expected=compare(d);
 d.findings.push(...d.findings.map(f=>({...f,id:'foreign-'+f.id,companyId:'FOREIGN',realRisk:100})));
 d.scans.push({id:'foreign',companyId:'FOREIGN',completedAt:new Date(h.now+day).toISOString(),vendor:{}});
 d.assets.push({id:'foreign',companyId:'FOREIGN',identifier:'host-1',hostname:'host-1',ipAddresses:[]});
 assert.deepEqual(transport(compare(d)),transport(expected));
});
test('configured SLA, exact deadline, Info and the 90-day resolution boundary match legacy',()=>{
 const d=data(1),base=d.findings[0];d.scans=[];d.assets=[];
 d.findings=[
  {...base,id:'exact',severity:'Critical',firstSeen:iso(1)},
  {...base,id:'before',severity:'Critical',firstSeen:new Date(h.now-day-1).toISOString()},
  {...base,id:'info',severity:'Info',firstSeen:iso(400)},
  {...base,id:'resolved90',status:'Resolved',firstSeen:iso(110),resolvedAt:iso(90)},
  {...base,id:'resolvedold',status:'Resolved',firstSeen:iso(111),resolvedAt:new Date(h.now-90*day-1).toISOString()},
 ];
 const result=compare(d);assert.equal(result.sla.bySeverity.Critical.overdue,1);assert.equal(result.sla.bySeverity.Info.overdue,0);assert.equal(result.sla.mttrDays,20);
 assert.notDeepEqual(transport(compare(d,{...sla,Critical:2}).posture),transport(result.posture));
});
test('coverage uses historical remediation findings and hostname/IP aliases, excluding OSINT-only observations',()=>{
 const d=data(2);d.findings[0].status='Resolved';d.findings[0].asset='  HOST-ALIAS  ';
 d.findings[1].connector='spiderfoot';d.findings[1].asset='osint-only';
 d.assets=[{id:'a',companyId:company.id,identifier:'x',hostname:'HOST-ALIAS',ipAddresses:[]},
  {id:'b',companyId:company.id,identifier:'osint-only',hostname:'other',ipAddresses:[]}];compare(d);
});
test('compliance catalog KEV is distinct from the saved finding flag; missing data is preserved',()=>{
 const d=data(1);d.findings[0].cve='CVE-2021-44228';d.findings[0].kev=false;
 compare(d);compare({findings:[],scans:[],assets:[]});
});
test('legacy OSINT financial and accepted-exposure semantics are preserved explicitly',()=>{
 const d=data(4);d.findings=d.findings.map((f,i)=>({...f,connector:'spiderfoot',severity:'Critical',status:['Open','Risk Accepted','False Positive','Resolved'][i]}));
 const report=compare(d);assert.equal(report.findings.open,0);assert.equal(report.attackSurface.total,3);assert.ok(report.financial.ale>0);
});
test('top-five ties retain persisted finding order and pending/failed completed scan evidence is preserved',()=>{
 const d=data(1),f=d.findings[0];d.findings=Array.from({length:12},(_,i)=>({...f,id:`tie-${i}`,title:`Tie ${i}`}));
 d.scans=[{id:'old',companyId:company.id,completedAt:iso(120),status:'Failed',vendor:{}},
  {id:'new',companyId:company.id,completedAt:iso(10),status:'Stopped',vendor:{}}];
 const report=compare(d);assert.deepEqual(transport(report.topRisks.map(r=>r.title)),['Tie 0','Tie 1','Tie 2','Tie 3','Tie 4']);
});
test('the accumulator cannot accept inventory before findings or reuse a finished report',()=>{
 const d=data(1),a=h.executive.createExecutiveReportAccumulator(company,{now:h.now,sla,isComplianceKev:h.threat.isKev});
 a.asset(d.assets[0]);assert.throws(()=>a.finding(d.findings[0]),/precede/);a.finish();assert.throws(()=>a.finish(),/already finished/);
});
test('the connected store keeps the unknown-customer result and does not leak contact metadata',()=>{
 h.setState(state(data(1)));assert.equal(h.store.computeExecReport('MISSING'),null);
 assert.deepEqual(Object.keys(h.store.computeExecReport(company.id).company).sort(),['id','industry','name']);
});
test('customer email preparation reuses the compatible report without sending anything',()=>{
 const s=state(data(300));h.setState(s);const expected=h.legacy.legacyExecutiveReport(h.store,s,company.id);
 const packet=h.store.buildCustomerReportData(company.id);assert.ok(!('error' in packet));
 assert.deepEqual(transport({...packet.report,generatedAt:''}),transport(expected));assert.equal(packet.report.generatedAt,new Date(h.now).toISOString());
 assert.ok(packet.topRisks.length<=10);assert.equal(packet.delta,null);
});
