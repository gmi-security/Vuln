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
const company={id:'CO-A',name:'Customer A'};
const cve='CVE-2026-1234',when='2026-10-09T12:00:00Z';
const finding=(changes={})=>({id:'f1',companyId:company.id,connector:'defender',cve,asset:'a-device',status:'Open',remediation:'Install recommended update',severity:'High',cvss:8.1,realRisk:72,lastSeen:when,...changes});
const cs=(changes={})=>({id:'cs1',cid:'cid-A',hostId:'device-1',hostname:'host-one',cve,severity:'Critical',cvss:9.8,exprt:'HIGH',risk:65,ip:'10.0.0.1',os:'Windows',hostCriticality:'Normal',apps:[],
  remediations:[{id:'r1',title:'Recommended patch',action:'Install recommended update',recommendationType:'recommended',reference:'KB1',vendorUrl:'',link:'',published:''}],...changes});
const model=await loadModule('lib/customer-cve-model.ts',{'./store':{getCompany:()=>company}});

test('CVE input canonicalization and exact customer, state and source filtering',()=>{
  assert.equal(model.customerCve('cve-2026-1234'),cve);
  assert.throws(()=>model.customerCve('CVE-1'),/valid CVE/);
  const rows=[finding(),finding({companyId:'CO-B'}),finding({status:'Resolved'}),finding({connector:'spiderfoot'})];
  assert.equal(model.openCustomerFindings(company.id,rows,cve).length,1);
});
test('manual draft uses only the selected customer and keeps assets out of ticket text',()=>{
  const [group]=model.buildCustomerCveGroups(company,cve,[finding(),finding({companyId:'CO-B',asset:'secret-other-host'})],[],new Set(),when);
  assert.equal(group.appCompanyId,company.id);assert.equal(group.manualOnly,true);
  assert.match(group.remediationId,/^manual:/);assert.match(group.csv,/a-device/);
  assert.doesNotMatch(JSON.stringify(group),/secret-other-host/);
  assert.doesNotMatch(group.ticketBody,/a-device/);assert.match(group.ticketBody,/8.1/);
});
test('CrowdStrike output deduplicates device/CVE evidence and includes scores and recommended action only',()=>{
  const row=cs({remediations:[...cs().remediations,{id:'minimum',action:'Unwanted minimum fix',recommendationType:'minimum'}]});
  const [group]=model.buildCustomerCveGroups(company,cve,[],[row,cs({id:'cs2'})],new Set(),when);
  assert.equal(group.deviceCount,1);assert.equal(group.deviceCves.length,1);
  assert.match(group.csv,/9.8/);assert.match(group.csv,/HIGH/);assert.match(group.csv,/cs1; cs2/);
  assert.match(group.csv,/Install recommended update/);assert.doesNotMatch(group.csv,/Unwanted minimum/);
  assert.match(group.ticketBody,/saved source data/);assert.doesNotMatch(group.ticketBody,/host-one/);
  assert.equal(group.source,'stored-findings');assert.equal(group.manualOnly,true);
});
test('missing recommended evidence fails the entire preparation rather than dropping hosts',()=>{
  assert.throws(()=>model.buildCustomerCveGroups(company,cve,[finding()], [cs({remediations:[]})],new Set(),when),/no partial request/);
  assert.throws(()=>model.buildCustomerCveGroups(company,cve,[finding({remediation:''})],[],new Set(),when),/no partial request/);
  assert.throws(()=>model.buildCustomerCveGroups(company,cve,[],[cs({apps:[{recommended:'missing',ids:['missing'],minimum:''}]})],new Set(),when),/no partial request/);
});
test('already-ticketed pairs are excluded without excluding other devices',()=>{
  const excluded=new Set([JSON.stringify(['cid-A','device-1',cve])]);
  const [group]=model.buildCustomerCveGroups(company,cve,[],[cs(),cs({hostId:'device-2'})],excluded,when);
  assert.equal(group.deviceCount,1);assert.doesNotMatch(group.csv,/device-1/);assert.match(group.csv,/device-2/);
});
test('source mismatch and over-limit input are rejected',()=>{
  assert.throws(()=>model.scopedSpotlightRows(company.id,cve,[{company_id:'CO-B',raw:{}}]),/selected customer/);
  assert.throws(()=>model.scopedSpotlightRows(company.id,cve,Array(10001).fill({})),/No partial/);
});

async function service({records=[],generation=null,findings=[finding()],tickets=[],prior=null}={}){
  const calls=[];let released=0;
  const query=async(sql,params=[])=>{
    calls.push({sql,params});
    if(sql.includes('to_regclass'))return{rows:[{spotlight:true,enrichment:false}]};
    if(sql.includes('FROM spotlight_import_current'))return{rows:generation?[generation]:[]};
    if(sql.includes('FROM spotlight_import_records'))return{rows:records};
    if(sql.includes('SELECT id,state,review_state'))return{rows:tickets};
    if(sql.includes("AND state='prepared'"))return{rows:prior?[{id:prior}]:[]};
    if(sql.includes("SELECT id FROM patch_group_ticket_requests WHERE id="))return{rows:[],rowCount:0};
    return{rows:[],rowCount:0};
  };
  const db={query,connect:async()=>({query,release:()=>released++})};
  const api=await loadModule('lib/customer-cve-service.ts',{
    './store':{listFindings:()=>findings,getCompany:()=>company},
    './customer-scope':{resolveCustomerScope:async id=>{if(id!==company.id)throw Error('Invalid customer');return{companyId:id,company};}},
    './persist':{applicationDatabase:()=>db},'./patch-ticket-store':{patchTicketDatabase:async()=>db},
  });return{api,calls,released:()=>released};
}
test('saved completed generation wins over stale normalized CrowdStrike data',async()=>{
  const {api,calls,released}=await service({generation:{run_id:'run-A',promoted_at:when},findings:[finding({connector:'crowdstrike'})]});
  await assert.rejects(()=>api.readCustomerCve(company.id,cve),/No open findings/);
  const q=calls.find(row=>row.sql.includes('FROM spotlight_import_records'));
  assert.deepEqual(q.params,[company.id,cve,10001,'run-A']);assert.match(q.sql,/r.company_id=\$1/);assert.match(q.sql,/r.tenant_key=\$1/);
  assert.ok(calls.some(row=>row.sql==='ROLLBACK'));assert.equal(released(),1);
});
test('detail cannot return another customer even if the source store returns mixed findings',async()=>{
  const {api,calls}=await service({findings:[finding(),finding({companyId:'CO-B',asset:'other-host'})]});
  const result=await api.readCustomerCve(company.id,cve);
  assert.equal(result.findingCount,1);assert.doesNotMatch(JSON.stringify(result),/other-host/);
  const ticketQuery=calls.find(row=>row.sql.includes('SELECT id,state,review_state'));
  assert.deepEqual(ticketQuery.params,[company.id,cve]);assert.match(ticketQuery.sql,/appCompanyId/);
});
test('prepare persists a customer-scoped manual draft and reuses an unchanged pending scope',async()=>{
  for(const prior of [null,'existing-request']){
    const {api,calls}=await service({prior,findings:[finding({realRisk:72.3})]});const result=await api.prepareCustomerCve(company.id,cve,'member');
    assert.equal(result.groups.length,1);assert.equal(result.groups[0].group.manualOnly,true);
    assert.equal(result.groups[0].group.appCompanyId,company.id);
    assert.equal(result.groups[0].group.maxRisk,72.3);
    if(prior)assert.equal(result.groups[0].id,prior);
    assert.ok(calls.some(row=>row.sql.includes(prior?'UPDATE patch_group_ticket_requests':'INSERT INTO patch_group_ticket_requests')));
    const write=calls.find(row=>row.sql.includes(prior?'UPDATE patch_group_ticket_requests':'INSERT INTO patch_group_ticket_requests'));
    assert.equal(write.params.at(-1),72,'legacy integer summary must not reject decimal source scores');
    assert.ok(calls.some(row=>row.sql.includes('group.prepared.manual')));
    assert.ok(calls.some(row=>row.sql==='COMMIT'));
  }
});
test('another customer request id and malformed UUID are not accessible through scoped actions',async()=>{
  const {api}=await service();
  await assert.rejects(()=>api.assertCustomerGroup(company.id,'00000000-0000-4000-8000-000000000001'),/not found for this customer/);
  await assert.rejects(()=>api.assertCustomerGroup(company.id,'------------------------------------'),/not found for this customer/);
});

test('threat intelligence reads only customer CVEs and scoped risk evidence; no feed or scoring writes',async()=>{
  const calls=[];
  const query=async(sql,params)=>{
    calls.push({sql,params});
    if(sql.includes('to_regclass'))return{rows:[{enrichment:true,risk:true}]};
    if(sql.includes('FROM cve_enrichment'))return{rows:[{cve,total:1,active_exploitation:true,active_exploitation_source:'MISP',updated_at:when}]};
    return{rows:[]};
  };
  const api=await loadModule('lib/customer-threat-intelligence.ts',{
    './customer-scope':{resolveCustomerScope:async()=>({companyId:company.id,company})},
    './store':{getCompany:()=>company,listFindings:()=>[finding(),finding({companyId:'CO-B',cve:'CVE-2026-9999'})]},
    './persist':{applicationDatabase:()=>({connect:async()=>({query,release(){}})})},
  });
  const data=await api.customerThreatIntelligence(company.id);
  assert.equal(data.total,1);assert.equal(data.rows[0].active_exploitation_source,'MISP');
  const lookup=calls.find(row=>row.sql.includes('FROM cve_enrichment'));
  assert.deepEqual(lookup.params,[company.id,[cve]]);assert.match(lookup.sql,/r.company_id=\$1/);
  assert.ok(calls.some(row=>row.sql==='BEGIN READ ONLY'));
  assert.ok(calls.every(row=>!/(INSERT|UPDATE|DELETE)/.test(row.sql)));
});

test('manual draft cannot be automatically sent; equivalent legacy ticket is checked before a manual send',async()=>{
  for(const actor of ['auto-create','member']){
    const calls=[];
    const query=async(sql,params)=>{
      calls.push({sql,params});
      if(sql.includes('SELECT * FROM patch_group_ticket_requests'))return{rows:[{state:'prepared',review_state:'approved',remediation_id:'manual:r1',tenant_id:'cid-A',scope_hash:'scope',packet:{manualOnly:true,source:'stored-findings'}}]};
      if(sql.includes('SELECT revision FROM patch_connectwise_connection'))return{rows:[{revision:1}]};
      if(sql.includes('SELECT id,ticket_id FROM patch_group_ticket_requests'))return{rows:[{id:'legacy',ticket_id:123}]};
      return{rows:[]};
    };
    const api=await loadModule('lib/patch-group-ticket-store.ts',{
      './patch-ticket-store':{patchTicketDatabase:async()=>({connect:async()=>({query,release(){}})}),savedConnection:async()=>({revision:1,target:'test'})},
      './elastic-dashboard-store':{verifyAgainstCrowdStrike:()=>{throw Error('No live CS calls');}},
      './reporting-tenant-scope':{customerFalconTenantIds:()=>[]},
      './reporting-direct-sources':{atlasFalconReviewPacket:()=>false},
    });
    await assert.rejects(()=>api.createGroupTicket('00000000-0000-4000-8000-000000000001',{
      routing:{companyId:1,boardId:1},title:'Test',body:'Review',connectionRevision:1},actor),actor==='auto-create'?/explicit manual sending/:/ticket #123/);
    assert.ok(calls.some(row=>row.sql==='ROLLBACK'));
    assert.ok(calls.every(row=>!sqlWrite(row.sql)));
    if(actor==='member')assert.deepEqual(calls.find(row=>row.sql.includes('SELECT id,ticket_id')).params[1],['r1','manual:r1']);
  }
  function sqlWrite(sql){return /^(INSERT|UPDATE|DELETE)/.test(sql);}
});
