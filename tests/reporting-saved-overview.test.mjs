import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule,createContext} from 'node:vm';
import ts from 'typescript';
import {reportingWorkerSettings} from '../lib/db/customer-reporting-worker.mjs';
const settings={VULN_REPORTING_SQL_READS:'true',VULN_REPORTING_SQL_CUSTOMERS:'CO-A',VULN_REPORTING_INPUT_REVISIONS:'true'};
async function harness(env=settings){
 const calls=[],context=createContext({process:{env},console});
 let state='available',review='reviewed',fail=false;
 class DashboardError extends Error{constructor(message,status){super(message);this.status=status;}}
 const deps={
  './persist':{applicationDatabase:()=>({connect:async()=>{calls.push('connect');return {
    release:()=>calls.push('release'),query:async(_sql,params)=>{calls.push('legacy:'+params[0]);return {rows:[{ts:'2026-10-09T00:00:00Z',data:{totalOpen:12}}]};}
   };}})},
  './elastic-dashboard':{DashboardError},
  './customer-connector-status-service':{readCustomerConnectorStatus:async id=>{calls.push('review:'+id);return {sourceSelection:{state:review,revision:4}};}},
  './db/connector-metadata.mjs':{readSavedApplicationCompanies:async()=>[{id:'CO-A',name:'A'},{id:'DEMO',name:'Demo',isDemo:true}]},
  './db/customer-reporting-sections.mjs':{readCustomerReportingSections:async(s,t,id,options)=>{
   calls.push('read:'+id);assert.notEqual(s,t);assert.equal(options.mode,'published');assert.equal(options.expectedReviewRevision,4);
   if(fail)throw Error('credential:SECRET');return {state,model:{company:{id,name:'A'}},
    ...(options.requireExecutive?{executive:{company:{id,name:'A',industry:'Fixture'},generatedAt:'',findings:{open:12},trend:[{totalOpen:10}]}}:{}),
    capturedAt:'2026-10-10T00:00:00Z',builtAt:'2026-10-10T00:00:20Z'};
  }},
 };
 const code=ts.transpileModule(await readFile('lib/reporting-saved-overview.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(code,{context});await mod.link(name=>{
  const values=deps[name];assert.ok(values,'Unexpected dependency '+name);
  return new SyntheticModule(Object.keys(values),function(){for(const [k,v] of Object.entries(values))this.setExport(k,v);},{context});
 });await mod.evaluate();return {api:mod.namespace,calls,state:v=>state=v,review:v=>review=v,fail:()=>fail=true};
}
test('disabled and nonselected customers use legacy reporting without database or connector checks',async()=>{
 const h=await harness({});assert.equal(await h.api.savedReportingOverview('CO-A'),null);assert.equal(await h.api.savedReportingSetup(),null);assert.deepEqual(h.calls,[]);
 const enabled=await harness();assert.equal(await enabled.api.savedReportingOverview('CO-B'),null);assert.deepEqual(enabled.calls,[]);
 for(const id of ['', '*','CO-A,CO-A'])assert.throws(()=>enabled.api.savedOverviewEnabled('CO-A',{...settings,VULN_REPORTING_SQL_CUSTOMERS:id}),/incomplete/);
});

test('executive opt-in returns the same saved generation time and full trend, with no legacy fallback on expiry',async()=>{
 const off=await harness();assert.equal(await off.api.savedReportingExecutive('CO-A'),null);assert.deepEqual(off.calls,[]);
 const h=await harness({...settings,VULN_REPORTING_EXECUTIVE_ENABLED:'true'});
 const saved=await h.api.savedReportingExecutive('CO-A');assert.equal(saved.report.findings.open,12);
 assert.equal(saved.report.generatedAt,saved.savedReport.capturedAt);assert.equal(saved.report.trend[0].totalOpen,10);
 h.state('stale');await assert.rejects(()=>h.api.savedReportingExecutive('CO-A'),e=>e.status===503);
 assert.equal(await h.api.savedReportingExecutive('CO-B'),null);
});
test('selected canonical customer shows labeled legacy rows without combining its current trend',async()=>{
 const h=await harness({...settings,VULN_REPORTING_SQL_CUSTOMERS:'CO-229336'});
 const result=await h.api.savedReportingOverview('CO-229336');
 assert.deepEqual(JSON.parse(JSON.stringify(result.model.legacyHistory)),[{ts:'2026-10-09T00:00:00Z',sourceCompanyId:'CO-9150',
  sourceCompanyName:'GMI Scans',open:12}]);
 assert.ok(h.calls.includes('legacy:CO-9150'));
});
test('selected Overview reads only current approved SQL output and releases both clients',async()=>{
 const h=await harness();const result=await h.api.savedReportingOverview('CO-A');assert.equal(result.model.company.id,'CO-A');assert.ok(result.savedReport.capturedAt);
 assert.deepEqual(h.calls,['review:CO-A','connect','connect','read:CO-A','release','release']);
 const setup=await h.api.savedReportingSetup();assert.equal(setup.companies.length,1);assert.equal(setup.companies[0].id,'CO-A');
});
test('stale, absent, revoked and failed SQL reads cannot fall back to aggregation or expose raw errors',async()=>{
 const h=await harness();for(const state of ['stale','not-ready']){h.state(state);await assert.rejects(()=>h.api.savedReportingOverview('CO-A'),e=>e.status===503&&/awaiting refresh/.test(e.message));}
 h.review('needs-review');h.calls.length=0;await assert.rejects(()=>h.api.savedReportingOverview('CO-A'),/assignments/);assert.deepEqual(h.calls,['review:CO-A']);
 h.review('reviewed');h.fail();await assert.rejects(()=>h.api.savedReportingOverview('CO-A'),e=>e.status===503&&!/SECRET/.test(e.message));
 assert.equal(h.calls.filter(v=>v==='connect').length,h.calls.filter(v=>v==='release').length);
});
test('published worker uses the application database explicitly; legacy private mode remains the default',()=>{
 const env={VULN_REPORTING_WORKER_ENABLED:'true',VULN_REPORTING_WORKER_CUSTOMERS:'CO-A',VULN_REPORTING_STORAGE:'published',
  VULN_REPORTING_INPUT_REVISIONS:'true',DATABASE_URL:'application',VULN_REPORTING_SOURCE_URL:'application',VULN_REPORTING_DATABASE_URL:'application'};
 assert.equal(reportingWorkerSettings(env).mode,'published');
 for(const patch of [{VULN_REPORTING_INPUT_REVISIONS:'false'},{VULN_REPORTING_SOURCE_URL:'elsewhere'},{VULN_REPORTING_DATABASE_URL:'elsewhere'},{VULN_REPORTING_STORAGE:'anything'}])
  assert.throws(()=>reportingWorkerSettings({...env,...patch}));
});
