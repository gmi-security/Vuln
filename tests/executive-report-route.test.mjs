import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
async function harness(saved){
 const calls=[];class DashboardError extends Error{constructor(message,status){super(message);this.status=status;}}
 const values={
  'next/server':{NextResponse:{json:(value,options)=>Response.json(value,options)}},
  '@/lib/store':{ensureHydrated:async()=>calls.push('hydrate'),computeExecReport:id=>{calls.push('aggregate');return {company:{id},generatedAt:''};}},
  '@/lib/persist':{loadMetricsHistory:async()=>{calls.push('history');return []; }},
  '@/lib/elastic-dashboard':{DashboardError},
  '@/lib/reporting-saved-overview':{savedReportingExecutive:async()=>{calls.push('saved');if(saved==='stale')throw new DashboardError('Awaiting refresh',503);return saved;}}
 };
 const code=ts.transpileModule(await readFile('app/api/report/[companyId]/route.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(code);await mod.link(name=>{assert.ok(values[name]);return new SyntheticModule(Object.keys(values[name]),function(){for(const[k,v]of Object.entries(values[name]))this.setExport(k,v);});});await mod.evaluate();
 return {calls,get:()=>mod.namespace.GET(new Request('http://fixture/report/CO-A'),{params:Promise.resolve({companyId:'CO-A'})})};
}
test('printable executive API uses the saved report without hydrating or aggregating',async()=>{
 const result={report:{company:{id:'CO-A'},generatedAt:'2026-10-10T00:00:00Z',trend:[{totalOpen:12}]},savedReport:{capturedAt:'2026-10-10T00:00:00Z'}};
 const h=await harness(result),res=await h.get();assert.equal(res.status,200);assert.deepEqual(await res.json(),result);assert.deepEqual(h.calls,['saved']);assert.equal(res.headers.get('cache-control'),'no-store');
});
test('stale SQL reports do not silently hydrate, while disabled customers retain the original route',async()=>{
 const stale=await harness('stale');assert.equal((await stale.get()).status,503);assert.deepEqual(stale.calls,['saved']);
 const legacy=await harness(null);assert.equal((await legacy.get()).status,200);assert.deepEqual(legacy.calls,['saved','hydrate','aggregate','history']);
});
