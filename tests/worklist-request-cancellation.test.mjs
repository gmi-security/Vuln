import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

async function load(file,stubs) {
 const code=ts.transpileModule(await readFile(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const module=new SourceTextModule(code);
 await module.link(name=>{const values=stubs[name];assert.ok(values,`Unexpected dependency ${name}`);
  return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});});
 await module.evaluate();return module.namespace;
}

for(const kind of ['top-fixes','patch-priority'])test(`${kind} GET passes the browser disconnect signal to its reader`,async()=>{
 const pending=Promise.withResolvers(),controller=new AbortController();let received;
 const read=async(...args)=>{received=args.at(-1);pending.resolve();await new Promise((resolve,reject)=>received.addEventListener('abort',()=>reject(received.reason),{once:true}));};
 const route=await load(`app/api/elastic-dashboard/${kind}/route.ts`,{
  '@/lib/elastic-dashboard-http':{dashboardAccess:async()=>{},dashboardJson:value=>value,dashboardFailure:error=>error},
  '@/lib/elastic-dashboard-store':{dashboardReadDatabase:()=>{}},
  '@/lib/customer-top-fixes':{readCustomerTopFixes:read},'@/lib/customer-patch-priority':{customerPatchPriority:read},
 });
 const request=new Request('http://localhost/api/elastic-dashboard/'+kind+'?companyId=fixture',{signal:controller.signal});
 const result=route.GET(request);await pending.promise;
 assert.equal(received,request.signal);controller.abort();assert.equal((await result).name,'AbortError');
});

test('priority wrapper carries cancellation to the shared top-fixes reader and skips ticket overlay',async()=>{
 const controller=new AbortController();let received,overlays=0;
 const query=async sql=>({rows:sql.includes('to_regclass')?[{installed:false}]:[]});
 const module=await load('lib/customer-patch-priority.ts',{
  './customer-top-fixes':{readCustomerTopFixes:async(...args)=>{received=args.at(-1);controller.abort();received.throwIfAborted();}},
  './customer-fix-ticket-status':{withFixTicketStatus:async()=>{overlays++;}},
  './persist':{applicationDatabase:()=>({connect:async()=>({query,release(){}})})},
  './elastic-dashboard':{DashboardError:class extends Error{}},
 });
 await assert.rejects(module.customerPatchPriority('fixture',()=>{},controller.signal),{name:'AbortError'});
 assert.equal(received,controller.signal);assert.equal(overlays,0);
});
