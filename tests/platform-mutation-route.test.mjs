import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
test('mutation success waits for a durable commit without replaying external actions',async()=>{
 let commit,handled=0,commits=0;
 const module=new SourceTextModule(ts.transpileModule(await readFile('lib/platform-mutation-route.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
 await module.link(()=>new SyntheticModule(['commitPlatformMutation'],function(){this.setExport('commitPlatformMutation',()=>{commits++;return new Promise((resolve,reject)=>{commit={resolve,reject};});});}));await module.evaluate();
 const handler=module.namespace.withDurablePlatformMutation(async()=>{handled++;return Response.json({saved:true});});
 let settled=false;const success=handler().then(r=>{settled=true;return r;});await new Promise(r=>setImmediate(r));assert.equal(settled,false);commit.resolve();assert.equal((await success).status,200);
 const failed=handler();await new Promise(r=>setImmediate(r));commit.reject(Error('fixture failure'));const response=await failed;assert.equal(response.status,503);assert.equal(handled,2);assert.equal(commits,2);
 const validation=await module.namespace.withDurablePlatformMutation(async()=>Response.json({error:'bad input'},{status:400}))();assert.equal(validation.status,400);assert.equal(commits,2);
});
