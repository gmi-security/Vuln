import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { SourceTextModule,SyntheticModule } from "node:vm";
import ts from "typescript";

async function harness() {
  const cache=new Map(),calls=[];
  const numeric={columns:[{name:"count",type:"long"}],rows:[[100]],truncated:false};
  let dashboard={canManage:true,storageReady:true,connected:true,crowdstrike:{connected:true},queries:[
    {id:"atlas",source:"elastic",title:"Atlas only",result:numeric},
    {id:"other",source:"crowdstrike",title:"Other customer",result:{...numeric,rows:[[5]]}},
  ]};
  const synthetic=values=>new SyntheticModule(Object.keys(values),function(){for(const [k,v] of Object.entries(values))this.setExport(k,v);});
  const store=synthetic({ensureHydrated:async()=>{},getCompany:id=>["ATLAS","OTHER","FOOTPRINT"].includes(id)?{id,isDemo:false}:null});
  const tiles=synthetic({readDashboard:async()=>{calls.push(["read"]);return dashboard;},triggerRefresh:(force,ids)=>calls.push(["refresh",force,ids])});
  async function load(path) {
    path=resolve(path);
    if(path === resolve("lib/store.ts"))return store;
    if(path === resolve("lib/elastic-dashboard-store.ts"))return tiles;
    if(cache.has(path))return cache.get(path);
    const m=new SourceTextModule(ts.transpileModule(await readFile(path,"utf8"),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});
    cache.set(path,m);
    await m.link(name=>load(name.startsWith("@/")?name.slice(2)+".ts":resolve(dirname(path),name+".ts")));
    return m;
  }
  const helper=await load("lib/reporting-customer-tiles.ts");await helper.evaluate();
  const csv=await load("lib/dashboard-csv.ts");await csv.evaluate();
  const previous={...process.env};
  process.env.REPORTING_CUSTOMER_TILE_IDS='{"ATLAS":["atlas"],"OTHER":["other"]}';delete process.env.ATLAS_REPORTING_TILE_IDS;
  return {helper:helper.namespace,csv:csv.namespace,calls,unavailable:()=>{dashboard={...dashboard,storageReady:false};},
    restore:()=>{for(const key of ["REPORTING_CUSTOMER_TILE_IDS","ATLAS_REPORTING_TILE_IDS"]){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}}};
}

test("Footprint and unselected reports do not even load the shared result cache",async t=>{
  const h=await harness();t.after(h.restore);
  assert.deepEqual((await h.helper.readCustomerTiles("FOOTPRINT",true)).queries,[]);
  assert.deepEqual((await h.helper.readCustomerTiles("",true)).queries,[]);
  assert.deepEqual(h.calls,[]);
  await assert.rejects(h.helper.readCustomerTiles("MISSING",true),/Customer not found/);
});

test("a scoped refresh contains only that customer's verified tile IDs and empty scope cannot refresh globally",async t=>{
  const h=await harness();t.after(h.restore);
  assert.deepEqual(await h.helper.refreshCustomerTiles("OTHER",true),{queued:true,count:1});
  assert.deepEqual(h.calls.filter(c=>c[0]==="refresh"),[["refresh",true,["other"]]]);
  assert.deepEqual(await h.helper.refreshCustomerTiles("FOOTPRINT",true),{queued:false,count:0});
  await assert.rejects(h.helper.refreshCustomerTiles("",true),/Choose a customer/);
  h.unavailable();await assert.rejects(h.helper.refreshCustomerTiles("ATLAS",true),/storage is unavailable/);
});

test("customer CSV contains only the response selected by the backend assignment",async t=>{
  const h=await harness();t.after(h.restore);
  const own=await h.helper.readCustomerTiles("OTHER",true);
  assert.equal(own.queries.length,1);
  assert.match(h.csv.dashboardCsv(own.queries[0].result),/"5"/);
  assert.doesNotMatch(h.csv.dashboardCsv(own.queries[0].result),/100|Atlas/);
});

test("bad mapping configuration returns an error rather than the shared dashboard",async t=>{
  const h=await harness();t.after(h.restore);
  process.env.REPORTING_CUSTOMER_TILE_IDS='{"ATLAS":["atlas"],"OTHER":["atlas"]}';
  await assert.rejects(h.helper.readCustomerTiles("OTHER",true),/assignments need to be checked/);
  assert.deepEqual(h.calls,[]);
});
