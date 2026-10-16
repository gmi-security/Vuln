import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';

async function harness(existing=false){
 const calls=[],never=()=>{throw Error('Provider call was not permitted.');};
 const client={query:async(sql,params=[])=>{
  calls.push({sql,params});
  if(sql.includes("SELECT revision FROM dashboard_source_connections"))return {rows:[{revision:1}]};
  if(sql.includes('SELECT id FROM patch_group_ticket_requests'))
   return {rows:existing?[{id:'existing-draft'}]:[]};
  return {rows:[]};
 },release:()=>{}};
 const deps={
  './elastic-dashboard':{DashboardError:class DashboardError extends Error{}},
  './patch-ticket-store':{patchTicketDatabase:async()=>({connect:async()=>client}),savedConnection:never},
  './elastic-dashboard-store':{verifyAgainstCrowdStrike:never,assertPatchRequestScope:never},
  './reporting-tenant-scope':{customerFalconTenantIds:never},
  './reporting-direct-sources':{atlasFalconReviewPacket:never},
  './patch-group-ticket-types':{automatedGroupTicketBody:never},
  './connectwise-client':Object.fromEntries(['cwId','cwRequest','findCWRequest','parseRouting','ticketUrl',
   'uploadPatchCsv','validateCWRouting'].map(name=>[name,never]).concat([['CWRequestError',class CWRequestError extends Error{}]])),
 };
 const source=ts.transpileModule(await readFile('lib/patch-group-ticket-store.ts','utf8'),
  {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
 const mod=new SourceTextModule(source);
 await mod.link(async name=>{
  if(name==='./customer-consolidation-hold'){
   const helper=new SourceTextModule(ts.transpileModule(await readFile('lib/customer-consolidation-hold.ts','utf8'),
    {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText);
   return helper;
  }
  const values=name==='node:crypto'?await import(name):deps[name];
  assert.ok(values,`Unexpected dependency ${name}`);
  return new SyntheticModule(Object.keys(values),function(){for(const [key,value] of Object.entries(values))this.setExport(key,value);});
 });
 await mod.evaluate();return {persist:mod.namespace.persistPreparedGroups,calls};
}
const group=id=>({appCompanyId:id,tenantId:id,remediationId:'remediation',hostScope:['host'],cves:['CVE-2026-1234'],
 worstSeverity:'High',maxRisk:70,deviceCount:1,findingCount:1});
const consolidation=id=>({groups:[group(id)],collectedAt:'2026-10-12T00:00:00Z'});

test('new canonical CrowdStrike draft is held before insertion without provider calls',async()=>{
 const h=await harness();await h.persist(consolidation('CO-229336'),'analyst',1);
 const insert=h.calls.find(call=>call.sql.includes('INSERT INTO patch_group_ticket_requests'));
 assert.equal(JSON.parse(insert.params[7]).manualOnly,true);
 assert.ok(h.calls.some(call=>call.sql==='COMMIT'));
});
test('reused canonical draft is upgraded to manualOnly; unrelated customer stays unchanged',async()=>{
 const held=await harness(true);await held.persist(consolidation('CO-229438'),'analyst',1);
 const heldUpdate=held.calls.find(call=>call.sql.includes('packet=CASE WHEN'));
 assert.equal(heldUpdate.params[3],true);
 const other=await harness();await other.persist(consolidation('CO-A'),'analyst',1);
 const insert=other.calls.find(call=>call.sql.includes('INSERT INTO patch_group_ticket_requests'));
 assert.equal(JSON.parse(insert.params[7]).manualOnly,undefined);
});
