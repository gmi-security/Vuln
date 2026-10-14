import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule,createContext} from 'node:vm';
import ts from 'typescript';

async function health(status,ping={ok:true},enabled=true){
 const context=createContext({process:{env:{}},Response});
 const modules={
  'next/server':{NextResponse:{json:(body,init)=>Response.json(body,init)}},
  'next-auth/jwt':{getToken:async()=>null},
  '@/lib/persist':{persistenceEnabled:()=>enabled,pingDb:async()=>ping,snapshotMeta:async()=>({updatedAt:null})},
  '@/lib/store':{storeStatus:async()=>({...status,counts:{private:123},oldestCompanyCreatedAt:'private'})},
 };
 const code=ts.transpileModule(await readFile('app/api/health/route.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const m=new SourceTextModule(code,{context});await m.link(name=>new SyntheticModule(Object.keys(modules[name]),function(){for(const[k,v]of Object.entries(modules[name]))this.setExport(k,v);},{context}));await m.evaluate();
 return m.namespace.GET({});
}
test('health reports failure when SQL is reachable but the app has blocked persistence',async()=>{
 const response=await health({hydrated:true,persistBlocked:true});
 assert.equal(response.status,503);const body=await response.json();assert.equal(body.ok,false);
 assert.equal(body.persistence.dbReachable,true);assert.equal(body.persistence.blocked,true);
 assert.equal(body.counts,undefined);assert.equal(body.oldestCompanyCreatedAt,undefined);
});
test('health distinguishes hydration from a ready saving application',async()=>{
 assert.equal((await health({hydrated:false,persistBlocked:false})).status,503);
 const response=await health({hydrated:true,persistBlocked:false});assert.equal(response.status,200);
 assert.equal((await response.json()).ready,true);
 assert.equal((await health({hydrated:true,persistBlocked:false},{ok:false,error:'private connection details'})).status,503);
});
test('an intentional in-memory preview is healthy once hydrated',async()=>{
 const response=await health({hydrated:true,persistBlocked:false},{ok:false},false);
 assert.equal(response.status,200);assert.equal((await response.json()).persistence.enabled,false);
});
