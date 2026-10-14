import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";
import ts from "typescript";

const company = { id:"CO-TEST", name:"Example Customer", kind:"client", industry:"Test", createdAt:"2026-10-01T00:00:00Z", contactName:"", contactEmail:"" };
const snapshot = { companyId:company.id, runId:"run-1", observedAt:"2026-10-07T12:00:00Z",
  devices:[{ deviceId:"device-1", hostname:"host-1", ip:"10.0.0.1", os:"Windows", lastSeen:"2026-10-07T12:00:00Z" }],
  findings:[{ deviceId:"device-1", hostname:"host-1", cve:"CVE-2026-12345", severity:"CRITICAL", cvss:9.8,
    firstSeen:"2026-10-01T00:00:00Z", lastSeen:"2026-10-07T12:00:00Z", remediation:"Install update", exploitAvailable:true }] };
const clone = value => JSON.parse(JSON.stringify(value));
const seed = () => ({ companies:[[company.id,company]], folders:[], scans:[], findings:[], assets:[], compensatingControls:[], identityAliases:[], counter:1000,
  settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},
  meta:{autoSyncDefaultMigrated:true,defenderGenerations:{}} });

async function harness(disk = { value:seed() }, strict = false) {
  const intervals = [], logs = [], modules = new Map();
  let failSave = false, saveCalls = 0, snapshotReads = 0, gate, lastChanges;
  const context = createContext({ Buffer, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, Response, Request, Headers, structuredClone,
    process:{ env:{VULN_DISABLE_SCHEDULER:"true"},once(){} },
    console:{ log:(...args)=>logs.push(args.join(" ")), info:(...args)=>logs.push(args.join(" ")), error:(...args)=>logs.push(args.join(" ")),warn(){} },
    setTimeout,clearTimeout,setImmediate,clearImmediate,
    setInterval:(fn,ms)=>{ intervals.push({fn,ms});return {unref(){}}; },clearInterval(){} });
  const synthetic = values => new SyntheticModule(Object.keys(values), function(){for(const key of Object.keys(values))this.setExport(key,values[key]);},{context});
  const persist = synthetic({
    persistenceEnabled:()=>true, applicationDatabase:()=>null,
    strictPlatformPersistence:()=>strict,
    loadSnapshot:async()=>clone(disk.value),
    saveSnapshot:async (value,options)=>{saveCalls++;if(gate)await gate;if(failSave)throw new Error("simulated database save failure");options?.guard?.();
      lastChanges=options?.changes;const next=clone(value);
      if(options?.changes!==undefined)for(const kind of ['companies','folders','scans','findings','assets']){
        const entries=new Map(disk.value[kind]),incoming=new Map(next[kind]);
        for(const id of options.changes[kind]??[])if(incoming.has(id))entries.set(id,incoming.get(id));else entries.delete(id);
        next[kind]=[...entries];
      }disk.value=next;},
    appendMetricsSnapshots:async()=>{},loadMetricsHistory:async()=>[],pingDb:async()=>({ok:true}),snapshotMeta:async()=>({updatedAt:null}),
  });
  const defender = synthetic({defenderStore:()=>({
    list:async()=>[{companyId:company.id,currentRun:snapshot.runId}],
    platformSnapshot:async()=>{snapshotReads++;return clone(snapshot);},
  })});
  async function moduleAt(path) {
    path=resolve(path);
    if(path === resolve("lib/persist.ts"))return persist;
    if(path === resolve("lib/defender-store.ts"))return defender;
    if(!modules.has(path))modules.set(path,(async()=>new SourceTextModule(ts.transpileModule(await readFile(path,"utf8"),{
      compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path,context}))());
    return modules.get(path);
  }
  async function linker(name,parent) {
    if(name.startsWith("."))return moduleAt(resolve(dirname(parent.identifier),`${name}.ts`));
    if(name.startsWith("@/"))return moduleAt(resolve(`${name.slice(2)}.ts`));
    const imported=await import(name);return synthetic(name === "rrule"?{...imported.default,...imported}:imported);
  }
  const mod=await moduleAt("lib/defender-platform.ts");await mod.link(linker);await mod.evaluate();
  const store=(await moduleAt("lib/store.ts")).namespace;
  await store.ensureHydrated();await context.__vulnFlushing;
  return { context,store,platform:mod.namespace,disk,logs,intervals,
    fail:()=>{failSave=true;},recover:()=>{failSave=false;},block:value=>{gate=value;},
    saves:()=>saveCalls,reads:()=>snapshotReads,changes:()=>lastChanges };
}

test("automatic snapshot saves retry after failure and save later mutations",async()=>{
  const h=await harness();
  assert.equal(h.context.__vulnFlushing,null,"initial save must release the in-flight guard");
  h.store.publishDefenderSnapshot(snapshot);h.fail();
  h.intervals.find(timer=>timer.ms === 6000).fn();await h.context.__vulnFlushing;
  assert.equal(h.context.__vulnDirty,true);assert.equal(h.context.__vulnFlushing,null);
  h.recover();h.intervals.find(timer=>timer.ms === 6000).fn();await h.context.__vulnFlushing;
  assert.equal(h.disk.value.findings.length,1);assert.equal(h.context.__vulnDirty,false);
  assert.equal(h.context.__vulnFlushing,null);
});

test("failed Defender save cannot report publication and the next pass retries without an API import",async()=>{
  const h=await harness();h.fail();
  await assert.rejects(h.platform.reconcileDefenderPlatform(false),/simulated database save failure/);
  assert.equal(h.store.defenderProjectedRun(company.id),undefined);
  assert.equal(h.disk.value.findings.length,0);
  assert.ok(!h.logs.some(line=>line.includes("Published completed generation")));
  h.recover();await h.platform.reconcileDefenderPlatform(false);
  assert.equal(h.reads(),2);assert.equal(h.disk.value.findings.length,1);
  assert.equal(h.disk.value.meta.defenderGenerations[company.id],snapshot.runId);
  assert.ok(h.logs.some(line=>line.includes("Published completed generation")));
});

test("saved Defender findings survive process restart and feed customer, global and executive totals",async()=>{
  const h=await harness();await h.platform.reconcileDefenderPlatform(false);
  const restarted=await harness(h.disk);
  assert.equal(restarted.store.defenderProjectedRun(company.id),snapshot.runId);
  assert.equal(restarted.store.computeMetrics({companyId:company.id}).totalOpen,1);
  assert.equal(restarted.store.computeMetrics({companyId:company.id}).severityCounts.Critical,1);
  assert.equal(restarted.store.computeMetrics().totalOpen,1);
  assert.equal(restarted.store.getCompany(company.id).openFindings,1);
  assert.equal(restarted.store.computeExecReport(company.id).findings.critical,1);
  assert.equal(restarted.store.listAssets({companyId:company.id})[0].openFindings,1);
  await restarted.platform.reconcileDefenderPlatform(false);
  assert.equal(restarted.reads(),0,"restart must reuse durable publication without another Microsoft import");
  assert.equal(restarted.store.computeMetrics({companyId:"different-customer"}).totalOpen,0);
});

test("a failed strict save does not poison later queued saves",async()=>{
  const h=await harness();h.fail();
  await assert.rejects(h.store.flushNow({throwOnError:true}));
  h.recover();h.store.publishDefenderSnapshot(snapshot);
  await h.store.flushNow({throwOnError:true});assert.equal(h.disk.value.findings.length,1);
});

test("restart repairs a saved generation marker whose platform findings are missing",async()=>{
  const h=await harness();await h.platform.reconcileDefenderPlatform(false);
  h.disk.value.findings=[];
  const restarted=await harness(h.disk);
  assert.equal(restarted.store.defenderProjectedRun(company.id),undefined);
  await restarted.platform.reconcileDefenderPlatform(false);
  assert.equal(restarted.store.computeMetrics({companyId:company.id}).totalOpen,1);
  assert.equal(restarted.disk.value.findings.length,1);
});

test("an in-flight snapshot cannot pick up a newer marker without that generation's findings",async()=>{
  const h=await harness();let release;
  h.block(new Promise(resolve=>{release=resolve;}));
  const saving=h.store.flushNow();await new Promise(resolve=>setImmediate(resolve));
  h.store.publishDefenderSnapshot(snapshot);release();await saving;
  assert.equal(h.disk.value.findings.length,0);
  assert.equal(h.disk.value.meta.defenderGenerations[company.id],undefined);
  assert.equal(h.context.__vulnDirty,true);
  h.block(undefined);await h.store.flushNow({throwOnError:true});
  assert.equal(h.disk.value.findings.length,1);
  assert.equal(h.disk.value.meta.defenderGenerations[company.id],snapshot.runId);
});

test("a later queued save keeps its guard while the previous save finishes",async()=>{
  const h=await harness();let release;
  h.block(new Promise(resolve=>{release=resolve;}));
  const first=h.store.flushNow(),second=h.store.flushNow();
  assert.ok(h.context.__vulnFlushing);release();await Promise.all([first,second]);
  assert.equal(h.context.__vulnFlushing,null);
});

test("publication stays pending until its database write completes",async()=>{
  const h=await harness();let release;
  h.block(new Promise(resolve=>{release=resolve;}));
  const publishing=h.platform.reconcileDefenderPlatform(false);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(h.platform.defenderPublicationPending(company.id),true);
  assert.ok(!h.logs.some(line=>line.includes("Published completed generation")));
  release();await publishing;
  assert.equal(h.platform.defenderPublicationPending(company.id),false);
  assert.equal(h.disk.value.findings.length,1);
});


test("SQL save failure blocks subsequent reads instead of serving uncommitted RAM",async()=>{
 const h=await harness(undefined,true),before=clone(h.disk.value);
 h.store.createCompany({name:"Unsaved customer",allowNearDuplicate:true});h.fail();
 await assert.rejects(h.store.commitPlatformMutation(),/simulated database save failure/);
 assert.equal(h.store.persistenceBlocked(),true);assert.deepEqual(h.disk.value,before);
 await assert.rejects(h.store.ensureHydrated(),/storage is unavailable/);
});
test("SQL capture retries when another mutation arrives during save",async()=>{
 const h=await harness(undefined,true);let release;h.block(new Promise(r=>{release=r;}));
 h.store.createCompany({name:"First customer",allowNearDuplicate:true});const pending=h.store.commitPlatformMutation();
 await new Promise(r=>setImmediate(r));h.store.createCompany({name:"Second customer",allowNearDuplicate:true});release();await pending;
 assert.ok(h.disk.value.companies.some(([,c])=>c.name==="First customer"));
 assert.ok(h.disk.value.companies.some(([,c])=>c.name==="Second customer"));assert.equal(h.store.persistenceBlocked(),false);
});

test("SQL analyst edits declare only their finding and preserve unrelated data and metadata",async()=>{
 const data=seed();data.futureMetadata={keep:'yes'};data.findings=[['F-one',{id:'F-one',companyId:company.id,status:'Open',assignee:null}],['F-two',{id:'F-two',companyId:company.id,status:'Open'}]];
 const h=await harness({value:data},true);h.store.updateFinding('F-one',{status:'In Remediation',assignee:'Team'});await h.store.commitPlatformMutation();
 assert.deepEqual(JSON.parse(JSON.stringify(h.changes())),{findings:['F-one']});
 assert.equal(h.disk.value.findings[0][1].status,'In Remediation');assert.equal(h.disk.value.findings[1][1].status,'Open');assert.deepEqual(h.disk.value.futureMetadata,{keep:'yes'});
 h.store.updateSettings({sla:{Critical:4}});await h.store.commitPlatformMutation();assert.deepEqual(JSON.parse(JSON.stringify(h.changes())),{});assert.equal(h.disk.value.findings.length,2);
});

test("SQL Defender publication scopes findings, assets, scan and folder without rewriting unrelated customers",async()=>{
 const data=seed();data.findings=[['unrelated',{id:'unrelated',companyId:'CO-OTHER',status:'Open'}]];
 const h=await harness({value:data},true);await h.platform.reconcileDefenderPlatform(false);
 assert.ok(h.changes(),'Defender must use a scoped publication');
 const changes=clone(h.changes());
 assert.equal(changes.findings.length,1);assert.ok(!changes.findings.includes('unrelated'));
 assert.equal(changes.assets.length,1);assert.deepEqual(changes.scans,[`defender:${company.id}`]);
 assert.equal(changes.folders.length,1);
 assert.equal(h.disk.value.meta.defenderGenerations[company.id],snapshot.runId);
 assert.ok(h.disk.value.findings.some(([id])=>id==='unrelated'));
 const restarted=await harness(h.disk,true);
 assert.equal(restarted.store.computeMetrics({companyId:company.id}).totalOpen,1);
});

test("SQL customer creation saves its new company, default folder and counter together",async()=>{
 const h=await harness(undefined,true);
 const created=h.store.createCompany({name:'Scoped creation fixture',allowNearDuplicate:true});assert.ok(!created.error);
 await h.store.commitPlatformMutation();const changes=JSON.parse(JSON.stringify(h.changes()));
 assert.deepEqual(changes.companies,[created.id]);assert.equal(changes.folders.length,1);assert.equal(changes.findings,undefined);
 assert.equal(h.disk.value.companies.find(([id])=>id===created.id)[1].name,'Scoped creation fixture');
 assert.equal(h.disk.value.folders.find(([id])=>id===changes.folders[0])[1].companyId,created.id);
 const restarted=await harness(h.disk,true),second=restarted.store.createCompany({name:'Next scoped customer',allowNearDuplicate:true});
 assert.notEqual(second.id,created.id);await restarted.store.commitPlatformMutation();
 assert.ok(restarted.disk.value.companies.some(([id])=>id===created.id));
});
