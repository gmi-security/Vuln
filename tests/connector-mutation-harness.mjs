// Real store/import logic; only persistence and explicitly supplied providers are fixtures.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createContext,SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';

export const clone=value=>JSON.parse(JSON.stringify(value));
export const company=(id='CO-A',name='Alpha')=>({id,name,kind:'client',industry:'Test',createdAt:'2026-10-01T00:00:00Z',contactName:'',contactEmail:''});
export const asset=(id='A-1',companyId='CO-A')=>({id,companyId,companyName:companyId==='CO-A'?'Alpha':'Beta',identifier:'host-1',hostname:'host-1',ipAddresses:['10.0.0.1'],source:'automate',externalId:'device-1',os:'Windows',owner:'',tags:[],criticality:'Normal',exposure:'Internal',lastSynced:'2026-10-01T00:00:00Z'});
export const finding=(id='F-1',companyId='CO-A')=>({id,companyId,companyName:companyId==='CO-A'?'Alpha':'Beta',scanId:'S-1',connector:'nessus',cve:'CVE-2026-12345',asset:'host-1',cvss:8,cvssV3:8,cvssV2:7,vpr:6,epss:0,exploitAvailable:false,severity:'High',title:'Patch fixture',description:'Evidence',remediation:'Install update',status:'Open',assignee:null,firstSeen:'2026-10-01T00:00:00Z',lastSeen:'2026-10-01T00:00:00Z',resolvedAt:null});
export const seed=()=>({companies:[['CO-A',company()],['CO-B',company('CO-B','Beta')]],folders:[],scans:[],findings:[],assets:[],compensatingControls:[],identityAliases:[],counter:1000,settings:{autoScanNewAssets:false,schedule:{autoSyncEnabled:false,autoSyncIntervalHours:24,alertsEnabled:false,monthlyReportsEnabled:false},sla:{Critical:7,High:30,Medium:60,Low:90}},meta:{autoSyncDefaultMigrated:true,nessusBackfillCorrected:true,defenderGenerations:{},lastAlertCheckAt:null,lastAutoSyncAt:null,lastMetricsSnapshotDay:null,lastMonthlyReportMonth:null,lastNessusFreshCheckAt:null,lastNessusFreshOk:null,lastNessusHealthCheckAt:null,lastNessusHealthOk:null,lastScannerElasticExportAt:null,lastSlaBreachCheckDay:null,lastVulnersBridgeSweepAt:null,nessusOffsetLastTriggered:{}}});
const compiled=new Map();
const exposed='\nexport {markDirty,nextId,upsertAsset,rescoreAllFindings,closeStaleFindings,importVendorFindings,refreshVendorScans,serializeStore,importEndpoints,applyTidalInventory,runZapScanAsync,runVulnersBridgeScanAsync};';

export async function mutationHarness({disk={value:seed()},providers={},baseline=false,now,fetch:transport}={}){
 const modules=new Map(),saves=[],timers=[],logs=[];let fail=false,gate;
 const Clock=now ? class extends Date {constructor(...args){super(...(args.length?args:[now]));}static now(){return new Date(now).getTime();}} : Date;
 const context=createContext({Date:Clock,Buffer,URL,URLSearchParams,TextEncoder,TextDecoder,AbortController,Response,Request,Headers,structuredClone,
  fetch:transport??(()=>{throw Error('Unexpected provider request in mutation fixture');}),
  process:{env:{VULN_DISABLE_SCHEDULER:'true'},once(){}},console:{log(){},info(){},error:(...args)=>logs.push(args.map(String).join(" ")),warn(){}},
  setTimeout,clearTimeout,setImmediate,clearImmediate,setInterval:(fn,ms)=>{timers.push({fn,ms});return {unref(){}};},clearInterval(){}});
 const synthetic=values=>new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v);},{context});
 const persist=synthetic({persistenceEnabled:()=>true,strictPlatformPersistence:()=>true,applicationDatabase:()=>null,
  loadSnapshot:async()=>clone(disk.value),loadCommittedRead:async()=>{throw Error('Unexpected web reader');},
  saveSnapshot:async(value,options)=>{
   if(gate)await gate();if(fail)throw Error('fixture save failed');options?.guard?.();options?.captureGuard?.();
   const next=clone(value),changes=options?.changes;saves.push({changes:changes===undefined?undefined:clone(changes),capture:clone(value)});
   if(changes!==undefined)for(const kind of ['companies','folders','scans','findings','assets']){
    const entries=new Map(disk.value[kind]),incoming=new Map(next[kind]);
    for(const id of changes[kind]??[])if(incoming.has(id))entries.set(id,incoming.get(id));else entries.delete(id);
    next[kind]=[...entries];
   }
   disk.value=next;
  },appendMetricsSnapshots:async()=>{},loadMetricsHistory:async()=>[],pingDb:async()=>({ok:true}),snapshotMeta:async()=>({updatedAt:null})});
 async function moduleAt(path){
  path=resolve(path);if(path===resolve('lib/persist.ts'))return persist;if(modules.has(path))return modules.get(path);
  const promise=(async()=>{
   if(!compiled.has(path))compiled.set(path,ts.transpileModule((await readFile(path,'utf8'))+(path===resolve('lib/store.ts')?exposed:''),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
   let code=compiled.get(path);
   const overrides=providers[path]??providers[Object.keys(providers).find(key=>resolve(key)===path)];
   if(overrides){
    const names=[...code.matchAll(/export\s+(?:async\s+)?(?:function\s*\*?|const|let|class)\s*(\w+)/g)].map(m=>m[1]);
    return synthetic(Object.fromEntries(names.map(name=>[name,overrides[name]??(()=>{throw Error(`Unexpected provider method ${name}`);})])));
   }
   // Comparison oracle: persist all records without changing importer behavior.
   if(baseline && path===resolve('lib/store.ts'))code=code.replace('function markDirty(changes) {','function markDirty(changes) { changes = undefined;');
   return new SourceTextModule(code,{identifier:path,context});
  })();modules.set(path,promise);return promise;
 }
 async function linker(name,parent){
  if(name.startsWith('.'))return moduleAt(resolve(dirname(parent.identifier),name.endsWith('.mjs')?name:`${name}.ts`));
  if(name.startsWith('@/'))return moduleAt(resolve(`${name.slice(2)}.ts`));
  const imported=await import(name);return synthetic(name==='rrule'?{...imported.default,...imported}:imported);
 }
 const mod=await moduleAt('lib/store.ts');await mod.link(linker);await mod.evaluate();const store=mod.namespace;
 await store.ensureHydrated();await context.__vulnFlushing;saves.length=0;
 return {store,context,disk,saves,timers,logs,memory:()=>context.__vulnStore,
  fail:()=>{fail=true;},recover:()=>{fail=false;context.__vulnPersistBlocked=false;},block:fn=>{gate=fn;},
  assertPersisted:()=>{const current=clone(store.serializeStore(context.__vulnStore));for(const key of ['companies','folders','scans','findings','assets','identityAliases','counter','settings','meta'])assert.deepEqual(disk.value[key],current[key],`Unsaved ${key}`);},
  flush:()=>store.flushNow({throwOnError:true}),lastScope:()=>saves.at(-1)?.changes};
}
