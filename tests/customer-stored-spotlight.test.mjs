import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

async function loadModule(entry, overrides={}) {
  const cache=new Map();
  function load(path) {
    path=resolve(path);if(cache.has(path))return cache.get(path);
    const source=readFileSync(path,'utf8');
    const mod=new SourceTextModule(ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{identifier:path});cache.set(path,mod);
    return mod;
  }
  function synthetic(values){return new SyntheticModule(Object.keys(values),function(){for(const key of Object.keys(values))this.setExport(key,values[key]);});}
  // Link the graph once. Recursively linking each dependency can return a cached
  // module while a sibling is still linking it, causing intermittent VM failures.
  const mod=load(entry);
  await mod.link(async(name,parent)=>{
    if(overrides[name]){const key=`override:${name}`;if(!cache.has(key))cache.set(key,synthetic(overrides[name]));return cache.get(key);}
    if(name.startsWith('.'))return load(resolve(dirname(parent.identifier),`${name}.ts`));
    if(name.startsWith('@/'))return load(resolve(`${name.slice(2)}.ts`));
    return synthetic(await import(name));
  });await mod.evaluate();return mod.namespace;
}

const company={id:'CO-A',name:'Customer A'},cve='CVE-2026-1234',when='2026-10-10T12:00:00Z';
const cid='a'.repeat(32),run='00000000-0000-4000-8000-000000000001',binding='b'.repeat(64);
const route={companyId:company.id,sourceScope:cid,bindingKey:binding};
const proof={version:1,companyId:company.id,runId:run,cid,bindingKey:binding};
const raw={id:'cs1',cid,aid:'device-1',status:'open',cve:{id:cve,base_score:9.8,severity:'CRITICAL'},host_info:{hostname:'fixture-host'},
  remediation:{entities:[{id:'r1',action:'Install recommended patch',recommendation_type:'recommended'}]}};
const record={company_id:company.id,source_id:'cs1',cve,status:'open',observed_at:when,raw};
const finding={id:'f1',companyId:company.id,connector:'defender',cve,asset:'platform-host',status:'Open',remediation:'Install patch',severity:'High',cvss:8,realRisk:65,lastSeen:when};
const completed={tenant_key:company.id,company_id:company.id,status:'completed',finished_at:when,checkpoint_version:4,expected_count:'1',hydrated_count:'1',cid,binding_key:binding};
process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS='crowdstrike';
async function fixture(options={}) {
  const calls=[];let active=0,contextCalls=0,commits=0;
  const query=async(sql,params=[])=>{
    calls.push({sql,params});
    if(sql==='COMMIT')commits++;
    if(sql.includes('to_regclass'))return {rows:[{spotlight:true,enrichment:false,runs:true,scopes:true,current:true,...options.tables}]};
    if(sql.includes('FROM spotlight_import_current'))return {rows:options.noGeneration?[]:[{run_id:options.currentRun??run,promoted_at:when}]};
    if(sql.includes('FROM spotlight_import_runs'))return {rows:options.missingRun?[]:[{...completed,...options.run}]};
    if(sql.includes('FROM spotlight_import_records'))return {rows:options.records??[record]};
    if(sql.includes('SELECT id,state,review_state')) {options.onTickets?.();return {rows:[]};}
    if(sql.includes('INSERT INTO patch_group_ticket_audit'))options.onAudit?.();
    return {rows:[],rowCount:0};
  };
  const db={query,connect:async()=>{assert.equal(active++,0,'no nested pool acquisition');return {query,release(){active--;}};}};
  const overrides={
    './persist':{applicationDatabase:()=>db},'./patch-ticket-store':{patchTicketDatabase:async()=>db},
    './store':{getCompany:()=>company,listFindings:()=>options.findings??[]},
    './customer-scope':{resolveCustomerScope:async()=>({companyId:company.id,company})},
    './customer-spotlight-routing-server':{loadReviewedSpotlightRoutes:async()=>{contextCalls++;return options.routes?options.routes(contextCalls):[route];}},
  };
  return {calls,query,api:await loadModule('lib/customer-cve-service.ts',overrides),guard:await loadModule('lib/customer-stored-spotlight.ts',overrides),
    dashboard:async()=>loadModule('lib/elastic-dashboard-store.ts',overrides),active:()=>active,commits:()=>commits};
}

test('reviewed CVE returns only pinned current evidence and stamps prepared packet; no nested pool acquisition',async()=>{
  const f=await fixture({findings:[{...finding,connector:'crowdstrike'}]});
  const detail=await f.api.readCustomerCve(company.id,cve);
  assert.equal(detail.findingCount,1);assert.equal(detail.hosts[0].host,'fixture-host');
  const prepared=await f.api.prepareCustomerCve(company.id,cve,'member'),packet=prepared.groups[0].group;
  assert.deepEqual(packet.storedSpotlightScope,proof);assert.equal(packet.manualOnly,true);
  assert.doesNotMatch(packet.csv,/platform-host/);assert.equal(f.active(),0);
  await f.guard.assertStoredSpotlightPacketScope(packet);
  const dashboard=await f.dashboard();await dashboard.assertPatchRequestScope(packet);
  assert.ok(f.calls.some(call=>call.sql.includes('INSERT INTO patch_group_ticket_requests')));
  assert.ok(f.calls.filter(call=>call.sql.includes('FROM spotlight_import_records')).every(call=>call.params[3]===run));
  assert.ok(f.calls.every(call=>!call.sql.includes('COUNT(')),'no whole-generation aggregation on request');
});

test('old, incomplete, foreign and stale pinned generations cannot fall back to RAM or write a draft',async()=>{
  for(const options of [
    {routes:()=>[]},{tables:{scopes:null}},{missingRun:true},
    ...[{checkpoint_version:3},{status:'running'},{finished_at:null},{tenant_key:'CO-B'},{company_id:'CO-B'},
      {cid:'c'.repeat(32)},{binding_key:'d'.repeat(64)},{expected_count:'0'},{hydrated_count:'0'},{expected_count:'9007199254740993'}].map(run=>({run})),
  ]) {
    const f=await fixture({...options,findings:[{...finding,connector:'crowdstrike'}]});
    await assert.rejects(()=>f.api.prepareCustomerCve(company.id,cve,'member'),/completed import/);
    assert.ok(f.calls.every(call=>!/^INSERT|^UPDATE/.test(call.sql)));assert.equal(f.active(),0);
  }
});

test('every selected raw row is validated before suppression and cannot override indexed CVE, identity or tenant',async()=>{
  const model=await loadModule('lib/customer-cve-model.ts',{'./store':{getCompany:()=>company}});
  for(const bad of [
    {...record,company_id:'CO-B'}, {...record,source_id:'different'}, {...record,cve:'CVE-2026-9999'}, {...record,status:'closed'},
    ...[{cid:'c'.repeat(32),suppression_info:{is_suppressed:true}},{cid:null},{aid:''},{id:''},{status:'closed'},{cve:{id:'CVE-2026-9999'}}].map(changes=>({...record,raw:{...raw,...changes}}))
  ])assert.throws(()=>model.scopedSpotlightRows(company.id,cve,[bad],cid),/customer|identity/);
  assert.equal(model.scopedSpotlightRows(company.id,cve,[{...record,raw:{...raw,cid:cid.toUpperCase()}}],cid)[0].cid,cid);
});

test('reviewed reads reject unprovable RAM and merged sources; unrelated Defender-only customers remain available',async()=>{
  for(const row of [{...finding,connector:'crowdstrike'}, {...finding,seenBy:['crowdstrike']}, {...finding,connector:'crowdstrike',defender:{active:true}}]){
    const f=await fixture({noGeneration:true,records:[],findings:[row]});
    await assert.rejects(()=>f.api.readCustomerCve(company.id,cve),/completed import|merged/);
  }
  const f=await fixture({noGeneration:true,routes:()=>[],findings:[finding]});
  assert.equal((await f.api.readCustomerCve(company.id,cve)).hosts[0].source,'defender');
  const group=(await f.api.prepareCustomerCve(company.id,cve,'member')).groups[0].group;
  assert.equal(group.storedSpotlightScope,undefined);await f.guard.assertStoredSpotlightPacketScope(group);
});

test('approval changes during ticket lookup or exclusions withhold detail and prevent preparation writes',async()=>{
  const f=await fixture({routes:n=>n===1?[route]:[]});
  await assert.rejects(()=>f.api.readCustomerCve(company.id,cve),/completed import/);
  const g=await fixture({routes:n=>n===1?[route]:[{...route,bindingKey:'d'.repeat(64)}]});
  await assert.rejects(()=>g.api.prepareCustomerCve(company.id,cve,'member'),/completed import/);
  assert.ok(g.calls.every(call=>!/^INSERT|^UPDATE/.test(call.sql)));
});

test('approval change during commit keeps an auditable pending draft but withholds the response and prevents sending',async()=>{
  let revoked=false;
  const f=await fixture({routes:()=>revoked?[]:[route],onAudit:()=>{revoked=true;}});
  await assert.rejects(()=>f.api.prepareCustomerCve(company.id,cve,'member'),/completed import/);
  const write=f.calls.find(call=>call.sql.includes('INSERT INTO patch_group_ticket_requests'));
  assert.ok(write);const packet=JSON.parse(write.params[5]);
  assert.equal(packet.manualOnly,true);assert.ok(f.commits()>1);
  await assert.rejects(()=>f.guard.assertStoredSpotlightPacketScope(packet),/completed import/);
});

test('pre-send guard rejects unproved historical, mixed and tampered host scopes and changed generation',async()=>{
  const f=await fixture(),packet=(await f.api.prepareCustomerCve(company.id,cve,'member')).groups[0].group;
  for(const changes of [
    {storedSpotlightScope:undefined},{appCompanyId:'CO-B'},{connectors:['defender','crowdstrike']},
    {tenantId:'c'.repeat(32)}, {hostScope:['not-json']}, {hostScope:[JSON.stringify(['c'.repeat(32),'device-1'])]},
    {deviceCves:[{cid,hostId:'different-device',cve}]}, {deviceCves:[]},
  ]) await assert.rejects(()=>f.guard.assertStoredSpotlightPacketScope({...packet,...changes}),/completed import/);
  const moved=await fixture({currentRun:'00000000-0000-4000-8000-000000000002'});
  await assert.rejects(()=>moved.guard.assertStoredSpotlightPacketScope(packet),/completed import/);
  const dashboard=await moved.dashboard();await assert.rejects(()=>dashboard.assertPatchRequestScope(packet),/completed import/);
});

test('default-off keeps legacy saved CrowdStrike packets and reads compatible',async()=>{
  const previous=process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS;
  process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS='';
  try {
    const f=await fixture({routes:()=>null,run:{checkpoint_version:3}});
    assert.equal((await f.api.readCustomerCve(company.id,cve)).findingCount,1);
    await f.guard.assertStoredSpotlightPacketScope({source:'stored-findings',connectors:['crowdstrike']});
    assert.ok(!f.calls.some(call=>call.sql.includes('FROM spotlight_import_runs')));
  } finally {process.env.VULN_REVIEWED_SPOTLIGHT_PROVIDERS=previous;}
});
