import assert from 'node:assert/strict';
import test from 'node:test';
import {loadReportingSections} from '../scripts/reporting-sections-loader.mjs';
const {create,reference}=await loadReportingSections();
export const company={id:'CO-REPORT',name:'Synthetic customer'};
export function reportingFixture(n=800){
 const connectors=['nessus','vulners','crowdstrike','defender','qualys','spiderfoot','artemis','burp','zap','nmap'];
 const statuses=['Open','In Remediation','Resolved','False Positive','Risk Accepted'];
 const severity=['Critical','High','Medium','Low','Info'];
 const findings=Array.from({length:n},(_,i)=>({id:`F-${i}`,companyId:company.id,connector:connectors[i%10],
  status:statuses[Math.floor(i/10)%5],severity:severity[Math.floor(i/50)%5],cve:i%9?'CVE-2026-1234':'EXPOSURE-1',
  realRisk:i%11,cvss:i%10,title:`Finding ${i}`,asset:`host-${i%30}`,lastSeen:`2026-10-${String(i%9+1).padStart(2,'0')}T01:00:00Z`,
  kev:i%3===0,exploitAvailable:i%4===0,assetSource:i%3===0?'tidal':i%3===1?'manual':'inferred',
  ...(i%7===0?{seenBy:['nessus','crowdstrike','nessus']}:{}),
  ...(i%13===0?{enrichments:[{source:'vulners',observedAt:'2026-10-10T01:00:00Z'}]}:{})}));
 const scans=Array.from({length:40},(_,i)=>({id:`S-${i}`,companyId:company.id,name:`Scan ${i}`,connector:connectors[i%10],
  status:['Completed','Failed','Running','Queued','Paused','Stopped'][i%6],createdAt:`2026-10-0${i%9+1}T00:00:00Z`,
  completedAt:i%6===0?'2026-10-10T00:00:00Z':null,findingsCount:i,hostsScanned:i+1}));
 const assets=Array.from({length:40},(_,i)=>({id:`A-${i}`,companyId:company.id,identifier:`host-${39-i}`,
  source:['tidal','manual','inferred','defender','intune'][i%5],lastSynced:'2026-10-09T00:00:00Z'}));
 const history=[{ts:'2026-10-09T00:00:00Z',data:{totalOpen:101}},{ts:'2026-10-10T00:00:00Z',data:{different:3}}];
 return {findings,scans,assets,history};
}
export function expectedReport(reference,data,owner=company){
 return reference(owner,[...data.findings].sort((a,b)=>b.realRisk-a.realRisk||b.cvss-a.cvss),
  [...data.scans].sort((a,b)=>b.createdAt>a.createdAt?1:-1),
  [...data.assets].sort((a,b)=>a.identifier.localeCompare(b.identifier)),data.history);
}
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
