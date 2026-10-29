import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
const cid='a'.repeat(32);
async function harness(options={}) {
 const calls=[],cache=new Map();let reads=0,contexts=0;
 const current={companyId:'A',source:'crowdstrike',state:'available',generation:{id:'current'},summary:{sourceInstances:2500239}};
 const query=async(sql,args)=>{
  calls.push({sql,args});assert.match(sql,/^(SELECT|BEGIN|SET|COMMIT|ROLLBACK)/);assert.doesNotMatch(sql,/spotlight_import_records|UPDATE|INSERT/);
  if(sql.includes('to_regclass'))return{rows:[{imports:true,summaries:true}]};
  if(sql.startsWith('SELECT run_id'))return{rows:options.noGeneration?[]:[{run_id:++reads>1&&options.changed?'next':'current'}]};
  if(sql.includes("summary->'vendorScope'"))return{rows:options.pending?[]:[{source_rows:10,vendor_scope:{version:2,tenantId:cid,mixed:!!options.mixed,missingRows:0,rows:10,localPlaceholderRows:0}}]};
  return{rows:[]};
 };
 const db={query,connect:async()=>({query,release(){}})};
 const stubs={
  './customer-saved-source-bindings':{createSavedSourceBindingSelector:()=>async()=>({sources:[],blocked:[]})},
  './persist':{applicationDatabase:()=>options.noDb?null:db},
  './customer-spotlight-routing-server':{loadReviewedSpotlightRoutes:async()=>{contexts++;if(options.error)throw Error('secret target');return options.blocked||options.changedContext&&contexts>1?[]:null;}},
  './spotlight-summary-store':{createSpotlightSummaryStore:()=>({read:async request=>{calls.push({read:request});return options.result??current;}})},
 };
 function load(file){if(cache.has(file))return cache.get(file);const mod=new SourceTextModule(ts.transpileModule(readFileSync(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:file});cache.set(file,mod);return mod;}
 async function link(name,parent){const v=stubs[name]??(!name.startsWith('.')?await import(name):null);if(v)return new SyntheticModule(Object.keys(v),function(){for(const[k,x]of Object.entries(v))this.setExport(k,x);});return load(resolve(dirname(parent.identifier),name+'.ts'));}
 const mod=load(resolve('lib/reporting-crowdstrike.ts'));await mod.link(link);await mod.evaluate();return{read:mod.namespace.reportingCrowdstrike,calls};
}
test('completed report reads verified summary with no legacy addition or raw source scan',async()=>{
 const h=await harness(),v=await h.read('A');assert.equal(v.state,'available');assert.equal(v.summary.sourceInstances,2500239);
 const r=h.calls.find(c=>c.read).read;assert.equal(r.companyId,'A');assert.equal(r.spotlightTenant,cid);assert.equal(r.limit,50);
});
test('customers without Spotlight imports retain platform reporting',async()=>{const h=await harness({noGeneration:true});assert.equal(await h.read('B'),null);assert.ok(!h.calls.some(c=>c.read));});
test('blocked scope, mixed tenants and wrong returned customer/source/generation withhold counts',async()=>{
 for(const options of [{blocked:true},{mixed:true},...['companyId','source'].map(k=>({result:{state:'available',companyId:'A',source:'crowdstrike',generation:{id:'current'},[k]:'wrong'}})),{result:{state:'available',companyId:'A',source:'crowdstrike',generation:{id:'old'}}}]){
  const h=await harness(options),v=await h.read('A');assert.equal(v.state,'unavailable');assert.equal(v.summary,undefined);
 }
});
test('missing summary remains pending and read errors do not leak details',async()=>{
 const h=await harness({pending:true});assert.match((await h.read('A')).message,/summary/i);assert.ok(!h.calls.some(c=>c.read));
 const failed=await harness({error:true});const v=await failed.read('A');assert.equal(v.state,'unavailable');assert.doesNotMatch(JSON.stringify(v),/secret/);
});
test('import or source approval changing during response cannot serve mismatched results',async()=>{
 for(const options of [{changed:true},{changedContext:true}]){const h=await harness(options);assert.equal((await h.read('A')).state,'unavailable');}
});

test('file-store customers without a CrowdStrike route retain the existing report',async()=>{const h=await harness({noDb:true});assert.equal(await h.read('B'),null);assert.equal(h.calls.length,0);});
