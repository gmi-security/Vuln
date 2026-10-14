import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {SourceTextModule,SyntheticModule} from "node:vm";
import test from "node:test";
import ts from "typescript";

test("retired auto-create endpoint authenticates and returns 410 without importing a database or provider",async()=>{
  let authorized=false, denied=false;
  const code=ts.transpileModule(await readFile("app/api/elastic-dashboard/patch-group-tickets/auto-create/route.ts","utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code);
  await mod.link(name=>{
    assert.equal(name,"@/lib/elastic-dashboard-http","Retired endpoint must not load a side-effecting service");
    return new SyntheticModule(["dashboardAccess","dashboardJson","dashboardFailure"],function(){
      this.setExport("dashboardAccess",async(_request,mutation)=>{assert.equal(mutation,true);if(denied)throw new Error("Unauthorized");authorized=true;});
      this.setExport("dashboardJson",(body,status)=>({body,status}));
      this.setExport("dashboardFailure",()=>({status:401}));
    });
  });
  await mod.evaluate();
  const result=await mod.namespace.POST(new Request("https://example.test/api/elastic-dashboard/patch-group-tickets/auto-create",{method:"POST"}));
  assert.equal(authorized,true);assert.equal(result.status,410);assert.match(result.body.error,/review and approve/);
  denied=true;assert.equal((await mod.namespace.POST({})).status,401);
});
