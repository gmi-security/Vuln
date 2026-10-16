import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve,dirname } from 'node:path';
import { SourceTextModule,SyntheticModule } from 'node:vm';
import ts from 'typescript';
const cid='a'.repeat(32),companyId='CO-147284';
const fix={companyId,calculatedAt:'2026-10-14T00:00:00Z',totalFixes:1,affectedDevices:20,findingCount:20,uniqueCves:1,missingRemediation:0,missingDevice:0,limit:50,
  rows:[{id:'saved',cve:'CVE-2026-1234',remediation:'Install recommended update',deviceCount:20,findingCount:20,maxRisk:60,severity:'High'}]};
async function harness(options={}) {
  const modules=new Map(),calls=[];let pointers=0;
  const query=async(sql,args)=>{
    assert.match(sql,/^(SELECT|SET|BEGIN|COMMIT|ROLLBACK)/);assert.doesNotMatch(sql,/spotlight_import_records|patch_group_ticket|UPDATE|INSERT/);
    calls.push({sql,args});
    if(sql.includes('to_regclass'))return {rows:[{imports:'spotlight_import_current',summaries:'spotlight_summary_generations'}]};
    if(sql.startsWith('SELECT run_id')) {pointers++;return {rows:options.noGeneration?[]:[{run_id:options.changeGeneration&&pointers>1?'next':'current'}]};}
    if(sql.includes("summary->'topFixes'"))return {rows:options.pending?[]:[{fixes:options.fixes??fix,source_rows:20,
      vendor_scope:{version:2,tenantId:cid,mixed:options.mixed??false,missingRows:0,rows:20,localPlaceholderRows:0}}]};
    return {rows:[]};
  };
  const db={query,connect:async()=>({query,release(){}})};
  const finding=(id,connector,extra={})=>({id,companyId,connector,cve:'CVE-2026-9999',asset:id,status:'Open',remediation:'Platform update',severity:'High',realRisk:60,...extra});
  const fakeStore={ensureHydrated:async()=>{},getCompanyIdentity:id=>id===companyId?{id,name:'Fixture'}:undefined,
    customerTopFixes:async(id,key,include)=>{const mod=await load(resolve('lib/reporting-top-fixes.ts'));if(mod.status==='unlinked')await mod.link(linker);await mod.evaluate();return mod.namespace.buildTopFixes(id,[finding('cs','crowdstrike'),finding('defender','defender'),finding('other','nessus',{companyId:'CO-OTHER'})],include);}};
  const stubs={'./persist':{applicationDatabase:()=>db},'./store':fakeStore,'./customer-spotlight-routing-server':{loadReviewedSpotlightRoutes:async()=>null}};
  function load(file) {
    if(modules.has(file))return modules.get(file);
    const code=ts.transpileModule(readFileSync(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
    const mod=new SourceTextModule(code,{identifier:file});modules.set(file,mod);return mod;
  }
  async function linker(name,parent) {
    const values=stubs[name] ?? (!name.startsWith('.')?await import(name):null);
    if(values)return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});
    return load(resolve(dirname(parent.identifier),name+'.ts'));
  }
  const module=load(resolve('lib/customer-top-fixes.ts'));await module.link(linker);await module.evaluate();
  return {read:module.namespace.readCustomerTopFixes,calls};
}
test('completed Spotlight summary replaces stale normalized CrowdStrike while retaining other customer findings',async()=>{
  const h=await harness(),r=await h.read(companyId);
  assert.equal(r.findingCount,21);assert.equal(r.affectedDevices,21);assert.equal(r.rows.length,2);
  assert.equal(r.rows[0].cve,'CVE-2026-1234');assert.equal(r.rows[0].source,'crowdstrike');
  assert.equal(r.rows[1].findingCount,1);assert.equal(r.rows[1].source,'platform');
  assert.ok(h.calls.filter(c=>c.args).every(c=>c.args[0]===companyId));
});

test('new remediation table merges customer-scoped summaries by severity without replacing existing rows',async()=>{
  const {cve,...rest}=fix.rows[0];
  const fixes={...fix,remediationWorklist:{totalGroups:1,limit:50,rows:[{...rest,severity:'Critical',cves:[cve],grouping:'vendor-remediation'}]}};
  const h=await harness({fixes}),r=await h.read(companyId);
  assert.equal(r.rows.length,2);
  assert.deepEqual(r.remediationWorklist.rows.map(row=>row.source),['crowdstrike','platform']);
  assert.equal(r.remediationWorklist.totalGroups,2);
  assert.deepEqual(r.remediationWorklist.rows[0].cves,[cve]);
  assert.ok(h.calls.some(c=>c.sql.includes('model_version IN (4,5,$3)')));
});

test('v4 summary preserves old table while additional worklist is pending; malformed v5 data is refused',async()=>{
  const old=await (await harness()).read(companyId);
  assert.equal(old.rows[0].source,'crowdstrike');assert.equal(old.remediationWorklist.rows.length,1);
  assert.match(old.remediationWorklist.notices[0],/waiting/);
  const h=await harness({fixes:{...fix,remediationWorklist:{totalGroups:1,limit:50,rows:[]}}});
  await assert.rejects(h.read(companyId),/inconsistent/);
});
test('missing source summary is explicitly pending and never falls back to stale CrowdStrike findings',async()=>{
  const h=await harness({pending:true}),r=await h.read(companyId);
  assert.equal(r.findingCount,1);assert.equal(r.rows[0].findingCount,1);assert.equal(r.notices.length,1);
  assert.match(r.notices[0],/waiting/);
});
test('customers without a completed Spotlight import retain their existing platform source population',async()=>{
  const h=await harness({noGeneration:true}),r=await h.read(companyId);
  assert.equal(r.findingCount,2);assert.equal(r.rows[0].deviceCount,2);assert.deepEqual(r.notices,[]);
});
test('unknown customers, cross-customer saved data, mixed tenant provenance and changing generations fail closed',async()=>{
  const h=await harness();await assert.rejects(h.read(null),e=>e.status===400);await assert.rejects(h.read('CO-OTHER'),e=>e.status===404);assert.equal(h.calls.length,0);
  for(const options of [{fixes:{...fix,companyId:'CO-OTHER'}},{fixes:{...fix,findingCount:0}},{mixed:true},{changeGeneration:true}]) {
    const scoped=await harness(options);await assert.rejects(scoped.read(companyId),e=>[409,503].includes(e.status));
  }
});
