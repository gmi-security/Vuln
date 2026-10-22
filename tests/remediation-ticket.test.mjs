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
const coverage=await loadModule('lib/patch-coverage.ts');
const model={...await loadModule('lib/remediation-ticket-model.ts'),...await loadModule('lib/remediation-ticket-packet.ts')};
const recommendations=await loadModule('lib/patch-recommendations.ts');
const cves=['CVE-2026-1234','CVE-2026-2345'];
const remedy={id:'r1',title:'Update Windows',action:'Install KB1',reference:'KB1',link:'',vendorUrl:'',published:'',recommendationType:'recommended'};
const row=(changes={})=>({id:'f1',cid:'a'.repeat(32),hostId:'h1',hostname:'private-host',ip:'10.0.0.1',os:'Windows',hostCriticality:'Normal',cve:cves[0],severity:'CRITICAL',cvss:9.8,exprt:'HIGH',risk:75,exploit:90,kev:true,...changes});
test('compact membership is lossless and rejects malformed or out of range coverage',()=>{
 const data={cves,hosts:[{cid:'tenant',hostId:'a',bits:'AQ=='},{cid:'tenant',hostId:'b',bits:'Ag=='}]};
 const parsed=coverage.readPatchCoverage(data);assert.equal(parsed.pairs,2);assert.equal(parsed.has('tenant','a',cves[0]),true);assert.equal(parsed.has('tenant','a',cves[1]),false);
 const pairs=new coverage.TicketedPairs();pairs.addCoverage(data,"manual:action-1");assert.ok(pairs.hasAction("tenant","b",cves[1],"action-1"));assert.equal(pairs.hasAction("other","b",cves[1],"action-1"),false);assert.equal(pairs.hasAction("tenant","b",cves[1],"action-2"),false);assert.equal(pairs.has(JSON.stringify(["tenant","b",cves[1]])),false);
 for(const bits of ['AA==','BA==','bad','AQAA'])assert.throws(()=>coverage.readPatchCoverage({cves,hosts:[{cid:'tenant',hostId:'a',bits}]}));
});
test('one action produces one draft with exact coverage, unique hosts and maximum scores',()=>{
 const acc=model.createRemediationEvidence();const id='crowdstrike:'+row().cid+':'+recommendations.remediationVariantId(remedy);
 acc.add(id,remedy,row());acc.add(id,remedy,row({id:'f2',cve:cves[1],severity:'LOW',cvss:2,risk:10}));acc.add(id,remedy,row({id:'f3',hostId:'h2',hostname:'second-host'}));
 const evidence=acc.finish([id])[id];const packet=model.remediationTicket({id:'CO-A',name:'Customer A'},evidence,'2026-10-16T00:00:00Z');
 assert.equal(packet.deviceCount,2);assert.equal(packet.findingCount,3);assert.equal(packet.cves.length,2);assert.equal(packet.worstSeverity,'Critical');assert.equal(packet.maxRisk,75);
 assert.equal(packet.reviewRows.length,2);assert.equal(packet.deviceCves.length,0);assert.equal(packet.manualOnly,true);assert.match(packet.csv,/private-host/);assert.doesNotMatch(packet.ticketBody,/private-host|10.0.0.1/);
 const parsed=coverage.readPatchCoverage(packet.deviceCveCoverage);assert.equal(parsed.pairs,3);assert.equal(parsed.has(row().cid,'h2',cves[1]),false);
 assert.equal(packet.csv.trim().split('\n').length,3);assert.match(packet.ticketBody,/9.8/);assert.match(packet.ticketBody,/KB1/);
});
test('target versions stay separate and high volume evidence stays compact',()=>{
 const acc=model.createRemediationEvidence();const variants=[remedy,{...remedy,action:'Install KB2',reference:'KB2'}];
 const ids=variants.map(r=>'crowdstrike:'+row().cid+':'+recommendations.remediationVariantId(r));
 for(let n=0;n<10000;n++)acc.add(ids[0],variants[0],row({id:'f'+n,hostId:'h'+(n%10),cve:'CVE-2026-'+(1000+Math.floor(n/10))}));
 acc.add(ids[1],variants[1],row());const result=acc.finish(ids);
 assert.equal(Object.keys(result).length,2);assert.equal(result[ids[0]].findingCount,10000);
 assert.equal(coverage.readPatchCoverage(result[ids[0]].coverage).pairs,10000);assert.ok(Buffer.byteLength(JSON.stringify(result))<50000);
 const packet=model.remediationTicket({id:'CO-A',name:'Customer A'},result[ids[0]],'2026-10-16T00:00:00Z');assert.equal(packet.deviceCount,10);assert.doesNotMatch(packet.ticketBody,/KB2/);
});
const cveModel=await loadModule('lib/customer-cve-model.ts',{'./store':{getCompany:()=>({id:'CO-A',name:'A'})}});
test('a compact ticket excludes only its action, preserves other target versions and rejects incomplete apps',()=>{
 const source={...row(),apps:[],remediations:[remedy],updated:'2026-10-16T00:00:00Z'};
 const pairs=new coverage.TicketedPairs();pairs.addCoverage({cves:[cves[0]],hosts:[{cid:source.cid,hostId:source.hostId,bits:'AQ=='}]},recommendations.remediationVariantId(remedy));
 assert.ok(coverage.ticketedFinding(pairs,source));
 const other={...remedy,id:'r2',action:'Install different product',reference:'KB2'};
 const mixed={...source,remediations:[remedy,other]};
 assert.equal(coverage.ticketedFinding(pairs,mixed),false);
 const groups=cveModel.buildCustomerCveGroups({id:'CO-A',name:'A'},cves[0],[],[mixed],pairs,'2026-10-16T00:00:00Z');
 assert.equal(groups.length,1);assert.equal(groups[0].action,other.action);
 const missing={...source,apps:[{recommended:'r1',ids:['r1']},{recommended:'',ids:[]}]};
 assert.equal(coverage.ticketedFinding(pairs,missing),false);
 assert.throws(()=>cveModel.buildCustomerCveGroups({id:'CO-A',name:'A'},cves[0],[],[missing],pairs,'2026-10-16T00:00:00Z'),/lacks recommended remediation/);
});
test('sparse evidence expansion is rejected before dense allocation and leaves normal summary work available',()=>{
 const acc=model.createRemediationEvidence(),id='one';
 for(let i=0;i<20000;i++)acc.add(id,remedy,row({hostId:'h'+i,cve:'CVE-2026-'+(1000+i)}));
 assert.deepEqual(acc.finish([id]),{});assert.match(acc.unavailableReason,/bounded summary capacity/);
});
test('optional priority actions cannot erase usable existing ticket evidence when serialization exceeds capacity',()=>{
 const acc=model.createRemediationEvidence();acc.add('existing',remedy,row());
 for(let i=0;i<20000;i++)acc.add('optional',remedy,row({hostId:'h'+i,cve:'CVE-2026-'+(1000+i)}));
 const result=acc.finish(['existing'],['optional']);assert.deepEqual(Object.keys(result),['existing']);
 assert.equal(result.existing.findingCount,1);assert.equal(acc.unavailableReason,undefined);
});
async function preparation(options={}){
 const acc=model.createRemediationEvidence(),id='crowdstrike:'+row().cid+':'+recommendations.remediationVariantId(remedy);acc.add(id,remedy,row());
 const evidence=acc.finish([id])[id],saved=[],calls=[];let pointers=0;
 const query=async(sql)=>{calls.push(sql);
  if(sql.includes('to_regclass'))return{rows:[{installed:true}]};
  if(sql.includes('FROM spotlight_import_current'))return{rows:[{run_id:options.changed&&++pointers>1?'next':'run1',promoted_at:'2026-10-16T00:00:00Z'}]};
  if(sql.includes("summary->'patchActions'"))return{rows:[{evidence:options.pending?null:evidence,source_rows:1,vendor_scope:{version:2,tenantId:row().cid,mixed:!!options.mixed,missingRows:0,rows:1,localPlaceholderRows:0}}]};
  return{rows:[]};
 };
 const db={query,connect:async()=>({query,release(){}})};
 const company={id:'CO-A',name:'A'};
 const api=await loadModule('lib/remediation-ticket-service.ts',{
  './customer-scope':{resolveCustomerScope:async id=>{if(id!==company.id)throw Error('Unknown customer');return {company};}},
  './customer-top-fixes':{readCustomerTopFixes:async()=>({remediationWorklist:{rows:[{id,source:'crowdstrike',cves:[cves[0]],findingCount:options.mismatch?2:1,deviceCount:1}]}})},
  './persist':{applicationDatabase:()=>db},'./store':{listFindings:()=>[],getCompany:()=>company},
  './customer-stored-spotlight':{storedSpotlightContext:async()=>({}),storedSpotlightProof:async()=>({cid:row().cid,companyId:company.id,runId:'run1'}),reviewedPlatformFindings:x=>x,recheckStoredSpotlightProof:async()=>{}},
  './customer-cve-service':{persistManualCustomerGroups:async(companyId,groups,actor,wholeAction)=>{saved.push({companyId,groups,actor,wholeAction});return groups.map(group=>({id:'draft',group}));}}
 });return {id,api,saved,calls};
}
test('row preparation loads only the selected saved action and creates a scoped manual draft',async()=>{
 const h=await preparation(),result=await h.api.prepareRemediationTicket('CO-A',h.id,'member');
 assert.equal(result.groups.length,1);assert.equal(h.saved.length,1);assert.equal(h.saved[0].wholeAction,true);assert.equal(h.saved[0].groups[0].manualOnly,true);
 assert.equal(h.calls.some(sql=>sql.includes('spotlight_import_records')),false);assert.ok(result.reviewUrl.includes('companyId=CO-A'));assert.equal('csv' in result.groups[0],false);
});
test('unknown action, missing summary, mixed tenant, changed counts and replaced import never save a partial draft',async()=>{
 for(const options of [{pending:true},{mixed:true},{mismatch:true},{changed:true}]){
  const h=await preparation(options);await assert.rejects(()=>h.api.prepareRemediationTicket('CO-A',h.id,'member'));assert.equal(h.saved.length,0);
 }
 const h=await preparation();await assert.rejects(()=>h.api.prepareRemediationTicket('CO-A','different-action','member'));await assert.rejects(()=>h.api.prepareRemediationTicket('CO-B',h.id,'member'));assert.equal(h.saved.length,0);
});
