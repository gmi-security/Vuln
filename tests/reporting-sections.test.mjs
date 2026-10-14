import assert from 'node:assert/strict';
import test from 'node:test';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
const {create,reference}=await loadReportingSections();
import {company,reportingFixture,expectedReport} from './reporting-sections-fixture.mjs';
function collect(data){const acc=create(company);for(const r of data.scans)acc.scan(r);for(const r of data.findings)acc.finding(r);
 for(const r of data.assets)acc.asset(r);return acc.finish(data.history);}
test('all platform finding classes, workflow states, scanner states, inventory and enrichment match current reporting',()=>{
 const data=reportingFixture();assert.deepEqual(collect(data).model,expectedReport(reference,data));
 assert.equal(collect(data).records,800);
});
test('10,000 mixed records preserve exact counts and bounded priority, exposure and web lists',()=>{
 const data=reportingFixture(10000),result=collect(data);assert.deepEqual(result.model,expectedReport(reference,data));
 assert.equal(result.model.priorityRows.length,25);assert.equal(result.model.attackSurfaceRows.length,10);
 assert.equal(result.model.webTestingRows.length,10);assert.equal(result.model.recentScans.length,12);
 assert.ok(JSON.stringify(result).length<40000);
});
test('no findings is not a completed clean scan; failed scans do not imply assessment',()=>{
 for(const scans of [[],[{id:'S',companyId:company.id,name:'Fail',connector:'nessus',status:'Failed',createdAt:'2026-01-01',completedAt:null}]]){
  const data={findings:[],assets:[],history:[],scans};assert.deepEqual(collect(data).model,expectedReport(reference,data));
  assert.equal(collect(data).model.assessmentState,'unassessed');
 }
});
test('completed clean endpoint, OSINT and web scans retain their distinct assessment semantics',()=>{
 for(const connector of ['nessus','crowdstrike','defender','spiderfoot','artemis','zap','burp']){
  const data={findings:[],assets:[],history:[],scans:[{id:'S',companyId:company.id,name:'Clean',connector,status:'Completed',createdAt:'2026-01-01',completedAt:'2026-01-02'}]};
  assert.deepEqual(collect(data).model,expectedReport(reference,data));
 }
});
test('equal risks preserve CVSS ordering in exposure/web; exact ties preserve map order',()=>{
 const data=reportingFixture(90);data.findings.forEach((f,i)=>{f.status='Open';f.realRisk=50;f.cvss=i%3;});
 assert.deepEqual(collect(data).model,expectedReport(reference,data));
});
test('same-date scans and same-identifier assets retain current stable ordering',()=>{
 const data=reportingFixture(1);data.scans.forEach(s=>s.createdAt='2026-01-01');data.assets.forEach(a=>a.identifier='same');
 assert.deepEqual(collect(data).model,expectedReport(reference,data));
});
test('customer mismatch and malformed core assessment fail instead of reporting partial clean totals',()=>{
 const acc=create(company),data=reportingFixture(1);
 for(const [name,records] of [['finding',data.findings],['scan',data.scans],['asset',data.assets]])
  assert.throws(()=>acc[name]({...records[0],companyId:'CO-OTHER'}),/customer|scope/);
 assert.throws(()=>acc.finding({...data.findings[0],severity:'UNKNOWN'}),/Invalid reporting finding/);
 assert.throws(()=>acc.finding({...data.findings[0],realRisk:NaN}),/Invalid reporting finding/);
});
