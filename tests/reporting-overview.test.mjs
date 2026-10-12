import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import {company,reportingFixture} from './reporting-sections-fixture.mjs';
const synthetic=values=>new SyntheticModule(Object.keys(values),function(){for(const [key,value] of Object.entries(values))this.setExport(key,value);});
async function harness(){
 const data=reportingFixture(),calls=[];let loggedIn=true,saved=null;
 class DashboardError extends Error{constructor(message,status){super(message);this.status=status;}}
 const stubs=new Map([
  [resolve("lib/reporting-saved-overview.ts"),synthetic({savedReportingOverview:async()=>{if(saved instanceof Error)throw saved;return saved;},savedReportingSetup:async()=>null})],
  [resolve('lib/elastic-dashboard.ts'),synthetic({DashboardError})],
  [resolve('lib/store.ts'),synthetic({ensureHydrated:async()=>{},getCompany:id=>id===company.id?company:id==='DEMO'?{id,isDemo:true}:null,
   listCompanies:()=>[company],computeExecReport:id=>{calls.push('executive');return {company:{id}};},
   listFindings:filter=>{calls.push('findings:'+filter.companyId);return data.findings;},
   listAssets:()=>data.assets,listScans:async()=>data.scans})],
  [resolve('lib/persist.ts'),synthetic({loadMetricsHistory:async()=>data.history,
   loadLegacyCustomerMetricsHistory:async()=>[]})],
  [resolve('lib/elastic-dashboard-http.ts'),synthetic({dashboardAccess:async()=>{if(!loggedIn)throw new DashboardError('Login required',401);},
   dashboardJson:value=>Response.json(value,{headers:{'cache-control':'no-store'}}),
   dashboardFailure:error=>Response.json({error:error.message},{status:error.status??500})})],
 ]);
 const cache=new Map();
 async function load(path){
  path=resolve(path);if(stubs.has(path))return stubs.get(path);if(cache.has(path))return cache.get(path);
  const mod=new SourceTextModule(ts.transpileModule(await readFile(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,mod);
  await mod.link(spec=>load(spec.startsWith('@/')?spec.slice(2)+'.ts':resolve(dirname(path),spec+'.ts')));return mod;
 }
 const service=await load('lib/reporting-store.ts');await service.evaluate();
 const route=await load('app/api/elastic-dashboard/reporting/route.ts');await route.evaluate();
 return {calls,saved:value=>saved=value,service:service.namespace,get:path=>route.namespace.GET(new Request('http://local/api/elastic-dashboard/reporting'+path)),logout:()=>{loggedIn=false;}};
}
test('Overview preserves complete report sections without computing the unused executive report',async()=>{
 const h=await harness();const sections=await h.service.reportingOverview(company.id);assert.deepEqual(h.calls,['findings:'+company.id]);
 const full=await h.service.reportingCustomer(company.id);assert.deepEqual(sections.model,full.model);assert.ok(h.calls.includes('executive'));
 assert.deepEqual(Object.keys(sections),['model']);
});
test('sections route retains access and explicit customer scope; unknown views cannot widen scope',async()=>{
 const h=await harness();
 const result=await h.get(`?companyId=${company.id}&view=sections`);assert.equal(result.status,200);assert.match(result.headers.get('cache-control'),/no-store/);
 assert.equal((await result.json()).model.company.id,company.id);assert.ok(!h.calls.includes('executive'));
 for(const query of ['?view=sections','?companyId=&view=sections','?companyId=DEMO&view=sections','?companyId=UNKNOWN&view=sections','?companyId=A&view=all'])
  assert.ok([400,404].includes((await h.get(query)).status));
 h.logout();assert.equal((await h.get(`?companyId=${company.id}&view=sections`)).status,401);
});
test('existing setup and full reporting response retain their contract',async()=>{
 const h=await harness();assert.deepEqual(await (await h.get('')).json(),{companies:[company]});
 const full=await (await h.get(`?companyId=${company.id}`)).json();
 assert.deepEqual(Object.keys(full).sort(),['insights','model','report','sources']);assert.ok(h.calls.includes('executive'));
});

test('selected SQL Overview bypasses legacy aggregation; errors propagate without implicit RAM fallback',async()=>{
 const h=await harness(),model={company};h.saved({model,savedReport:{capturedAt:'2026-10-10T00:00:00Z'}});
 const response=await h.get(`?companyId=${company.id}&view=sections`);assert.equal(response.status,200);assert.deepEqual((await response.json()).model,model);assert.deepEqual(h.calls,[]);
 h.saved(Object.assign(Error('Saved report awaiting refresh'),{status:503}));assert.equal((await h.get(`?companyId=${company.id}&view=sections`)).status,503);assert.deepEqual(h.calls,[]);
 h.logout();assert.equal((await h.get(`?companyId=${company.id}&view=sections`)).status,401);assert.deepEqual(h.calls,[]);
});
