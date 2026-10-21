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

async function service({records=[],generation=null,findings=[finding()],tickets=[],prior=null,sourceError=null,defenderRecords=[],defenderError=null,activeGroups=[]}={}){
  const calls=[];let released=0;
  const query=async(sql,params=[])=>{
    calls.push({sql,params});
    if(sql.includes('to_regclass'))return{rows:[{spotlight:true,enrichment:false}]};
    if(sql.includes('FROM spotlight_import_current'))return{rows:generation?[generation]:[]};
    if(sql.includes('FROM spotlight_import_records')){if(sourceError)throw sourceError;return{rows:records};}
    if(sql.includes('FROM defender_records')){if(defenderError)throw defenderError;return{rows:defenderRecords};}
    if(sql.includes("AS devices,packet->'deviceCveCoverage'"))return{rows:activeGroups};
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

const defenderRun='00000000-0000-4000-8000-000000000001';
const publishedDefenderFinding=(id,deviceId)=>finding({id,asset:deviceId,remediation:`windows_11 · installed-${id} · Security Updates · 5127648`,
  defender:{runId:defenderRun,deviceId,active:true,remediation:`windows_11 · installed-${deviceId} · Security Updates · 5127648`}});
const defenderRecord=(deviceId,changes={})=>({run_id:defenderRun,device_id:deviceId,softwareVendor:'microsoft',softwareName:'windows_11',
  softwareVersion:`installed-${deviceId}`,remediation:'Security Updates',remediationId:'5127648',...changes});

test('manual preparation uses structured Defender evidence from the published run, customer, CVE and devices only',async()=>{
  const findings=[publishedDefenderFinding('f1','d1'),publishedDefenderFinding('f2','d2')];
  const {api,calls}=await service({findings,defenderRecords:[defenderRecord('d1'),defenderRecord('d2'),defenderRecord('foreign'),defenderRecord('d1',{run_id:'another-run',remediationId:'BAD'})]});
  const result=await api.prepareCustomerCve(company.id,cve,'member');
  assert.equal(result.groups.length,1);
  const group=result.groups[0].group;
  assert.equal(group.deviceCount,2);assert.equal(group.title,'Windows 11 — Install KB5127648');
  assert.match(group.csv,/installed-d1/);assert.match(group.csv,/installed-d2/);
  assert.doesNotMatch(JSON.stringify(result),/foreign|BAD/);
  const query=calls.find(c=>c.sql.includes('FROM defender_records'));
  assert.equal(query.params[0],company.id);assert.equal(query.params[1],cve);
  assert.deepEqual(JSON.parse(query.params[2]),[{run_id:defenderRun,device_id:'d1'},{run_id:defenderRun,device_id:'d2'}]);
  assert.equal(query.params[3],10001);
  assert.match(query.sql,/runs.company_id=\$1/);assert.match(query.sql,/r.cve=\$2/);
  assert.match(query.sql,/runs.status='succeeded'/);
  assert.doesNotMatch(query.sql,/current_run/);
  assert.ok(calls.some(c=>c.sql==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  const prior=calls.find(c=>c.sql.includes('FOR UPDATE'));
  assert.match(prior.sql,/review_state='pending'/,'never overwrite approved or dismissed drafts');
});

test('opening a CVE does not perform the extra Defender patch lookup',async()=>{
  const {api,calls}=await service({findings:[publishedDefenderFinding('f1','d1')]});
  await api.readCustomerCve(company.id,cve);
  assert.ok(calls.every(c=>!c.sql.includes('FROM defender_records')));
});

test('missing retained Defender records keep every device with its exact saved remediation',async()=>{
  const {api}=await service({findings:[publishedDefenderFinding('f1','d1'),publishedDefenderFinding('f2','d2')],defenderRecords:[defenderRecord('d1')]});
  const result=await api.prepareCustomerCve(company.id,cve,'member');
  assert.equal(result.groups.length,2);
  assert.equal(result.groups.reduce((n,{group})=>n+group.deviceCount,0),2);
  assert.ok(result.groups.some(({group})=>group.action.includes('installed-f2')));
});

test('Defender source overflow and timeouts stop before any partial draft is saved',async()=>{
  for(const options of [{defenderRecords:Array(10001).fill(defenderRecord('d1'))},{defenderError:Object.assign(new Error('timeout'),{code:'57014'})}]) {
    const {api,calls,released}=await service({findings:[publishedDefenderFinding('f1','d1')],...options});
    await assert.rejects(()=>api.prepareCustomerCve(company.id,cve,'member'),e=>[413,504].includes(e.status));
    assert.ok(calls.some(c=>c.sql==='ROLLBACK'));assert.equal(released(),1);
    assert.ok(calls.every(c=>!/^\s*(INSERT|UPDATE|DELETE)\b/i.test(c.sql)));
  }
});

test('a partially pruned Defender run cannot drop installed versions or another required update',async()=>{
  for(const extra of [defenderRecord('d1',{softwareVersion:'second-installed-build'}),defenderRecord('d1',{remediationId:'5126653'})]) {
    const item=publishedDefenderFinding('f1','d1');
    const line=[extra.softwareName,extra.softwareVersion,extra.remediation,extra.remediationId].join(' · ');
    item.defender.remediation+='\n'+line;item.remediation=item.defender.remediation;
    const {api}=await service({findings:[item],defenderRecords:[defenderRecord('d1')]});
    const {groups}=await api.prepareCustomerCve(company.id,cve,'member');
    assert.equal(groups.length,1);assert.equal(groups[0].group.title,`${cve} remediation`);
    assert.ok(groups[0].group.ticketBody.includes(line));
  }
});

test('ticketing one Defender update does not hide another required update for the same device/CVE',async()=>{
  const item=publishedDefenderFinding('f1','d1'),records=[defenderRecord('d1'),defenderRecord('d1',{remediationId:'5126653'})];
  item.defender.remediation=records.map(r=>[r.softwareName,r.softwareVersion,r.remediation,r.remediationId].join(' · ')).join('\n');
  item.remediation=item.defender.remediation;
  const first=await service({findings:[item],defenderRecords:records});
  const prepared=await first.api.prepareCustomerCve(company.id,cve,'member');
  const ticketed=prepared.groups.find(({group})=>group.reference==='KB5127648').group;
  assert.equal(ticketed.deviceCves.length,1,'retain device/CVE evidence for review and verification');
  const second=await service({findings:[item],defenderRecords:records,activeGroups:[{
    devices:ticketed.deviceCves,coverage:ticketed.deviceCveCoverage,remediation_id:ticketed.remediationId,
  }]});
  const remaining=await second.api.prepareCustomerCve(company.id,cve,'member');
  assert.equal(remaining.groups.length,1);assert.equal(remaining.groups[0].group.reference,'KB5126653');
});
test('saved completed generation wins over stale normalized CrowdStrike data',async()=>{
  const {api,calls,released}=await service({generation:{run_id:'run-A',promoted_at:when},findings:[finding({connector:'crowdstrike'})]});
  await assert.rejects(()=>api.readCustomerCve(company.id,cve),/No open findings/);
  const q=calls.find(row=>row.sql.includes('FROM spotlight_import_records'));
  assert.deepEqual(q.params,[company.id,cve,10001,'run-A']);assert.match(q.sql,/r.company_id=\$1/);assert.match(q.sql,/r.tenant_key=\$1/);
  assert.ok(calls.some(row=>row.sql==='ROLLBACK'));assert.equal(released(),1);
});

test('variant actions on the same device keep their own finding evidence and scores',()=>{
  const first=cs({id:'first',risk:90}),second=cs({id:'second',risk:15,severity:'Low'});
  second.remediations[0].action='Install another target version';second.remediations[0].reference='KB2';
  const groups=model.buildCustomerCveGroups(company,cve,[],[first,second],new Set(),when);
  assert.equal(groups.length,2);
  const high=groups.find(g=>g.action===first.remediations[0].action),low=groups.find(g=>g.action===second.remediations[0].action);
  assert.equal(high.maxRisk,90);assert.equal(low.maxRisk,15);
  assert.match(high.csv,/first/);assert.doesNotMatch(high.csv,/second/);
  assert.match(low.csv,/second/);assert.doesNotMatch(low.csv,/first/);
});
test('a timed-out CVE read reports a timeout and rolls back without preparing a partial draft',async()=>{
  for(const action of ['readCustomerCve','prepareCustomerCve']){
    const {api,calls,released}=await service({generation:{run_id:'run-A',promoted_at:when},
      sourceError:Object.assign(new Error('canceling statement due to statement timeout'),{code:'57014'})});
    await assert.rejects(()=>api[action](company.id,cve,'member'),error=>error.status===504 && error.retryable===false && /CVE evidence.*too long/i.test(error.message));
    assert.ok(calls.some(row=>row.sql==='ROLLBACK'));assert.equal(released(),1);
    assert.ok(calls.every(row=>!/^\s*(INSERT|UPDATE|DELETE)\b/i.test(row.sql)));
    assert.equal(calls.filter(row=>row.sql.includes('FROM spotlight_import_records')).length,1,'do not retry an expensive query automatically');
  }
});
test('an unrelated CVE storage failure keeps its original error for the storage error handler',async()=>{
  const failure=Object.assign(new Error('connection lost'),{code:'08006'});
  const {api,released}=await service({generation:{run_id:'run-A',promoted_at:when},sourceError:failure});
  await assert.rejects(()=>api.readCustomerCve(company.id,cve),error=>error===failure);
  assert.equal(released(),1);
});
test('the HTTP error response preserves no-retry intent without exposing unknown storage errors',async()=>{
  const dashboard=await loadModule('lib/elastic-dashboard.ts');
  const http=await loadModule('lib/elastic-dashboard-http.ts',{
    './elastic-dashboard':dashboard,'./auth':{authOptions:{}},
    './elastic-vuln-server':{elasticVulnEnabled:()=>true},
    'next-auth':{getServerSession:async()=>null},
    'next/server':{NextResponse:{json:(value,options)=>Response.json(value,options)}},
  });
  const response=http.dashboardFailure(new dashboard.DashboardError('CVE lookup timed out',504,false));
  assert.equal(response.status,504);assert.deepEqual(await response.json(),{error:'CVE lookup timed out',retryable:false});
  const unavailable=http.dashboardFailure(new Error('private database connection details'));
  assert.equal(unavailable.status,503);
  const value=await unavailable.json();assert.equal(value.retryable,undefined);assert.doesNotMatch(value.error,/private database/);
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

test('manual drafts require approval and both legacy/variant send paths check equivalent action metadata',async()=>{
  for(const [actor,variant] of [['auto-create',false],['member',false],['member',true]]){
    const packet={manualOnly:true,source:'stored-findings',title:'Update',action:'Install version 3',reference:'3',link:'',vendorUrl:'',published:'',
      ...(variant?{vendorRemediationId:'r1'}:{})};
    const remediationId=variant?'manual:r1:variant':'manual:r1';
    const calls=[];
    const query=async(sql,params)=>{
      calls.push({sql,params});
      if(sql.includes('SELECT * FROM patch_group_ticket_requests'))return{rows:[{state:'prepared',review_state:'approved',remediation_id:remediationId,tenant_id:'cid-A',scope_hash:'scope',packet}]};
      if(sql.includes('SELECT revision FROM patch_connectwise_connection'))return{rows:[{revision:1}]};
      if(sql.includes('SELECT id,ticket_id FROM patch_group_ticket_requests'))return{rows:[{id:'legacy',ticket_id:123}]};
      return{rows:[]};
    };
    const api=await loadModule('lib/patch-group-ticket-store.ts',{
      './patch-ticket-store':{patchTicketDatabase:async()=>({query,connect:async()=>({query,release(){}})}),savedConnection:async()=>({revision:1,target:'test'})},
      './elastic-dashboard-store':{assertPatchRequestScope:async()=>{},verifyAgainstCrowdStrike:()=>{throw Error('No live CS calls');}},
      './reporting-tenant-scope':{customerFalconTenantIds:()=>[]},
      './reporting-direct-sources':{atlasFalconReviewPacket:()=>false},
    });
    await assert.rejects(()=>api.createGroupTicket('00000000-0000-4000-8000-000000000001',{
      routing:{companyId:1,boardId:1},title:'Test',body:'Review',connectionRevision:1},actor),actor==='auto-create'?/explicit manual sending/:/ticket #123/);
    assert.ok(calls.some(row=>row.sql==='ROLLBACK'));
    assert.ok(calls.every(row=>!sqlWrite(row.sql)));
    if(actor==='member'){
      const lookup=calls.find(row=>row.sql.includes('SELECT id,ticket_id'));
      assert.deepEqual(lookup.params[1],variant?['r1:variant','manual:r1:variant']:['r1','manual:r1']);
      assert.deepEqual(lookup.params[6],variant?['r1','manual:r1']:[]);
      assert.equal(lookup.params[7],variant?null:'r1');
      assert.equal(JSON.parse(lookup.params[8]).action,'Install version 3');
      assert.match(lookup.sql,/packet @> \$9::jsonb/);
    }
  }
  function sqlWrite(sql){return /^(INSERT|UPDATE|DELETE)/.test(sql);}
});
