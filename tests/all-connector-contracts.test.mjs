import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {SourceTextModule,SyntheticModule} from 'node:vm';
import ts from 'typescript';
import {createServer} from 'node:http';
import {loadConnectorPreview,loadConnectorContracts,loadConnectorRouting,loadConnectorReview} from '../scripts/connector-preview-loader.mjs';
const build=await loadConnectorPreview(),contracts=await loadConnectorContracts(),routing=await loadConnectorRouting(),review=await loadConnectorReview();
const metadata={companies:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],defender:[{companyId:'A',tenantId:'tenant-a',revision:1}],spotlight:[],connections:[{source:'elastic',revision:1},{source:'crowdstrike',revision:1}],tiles:[{id:'tile-a',companyId:'A',source:'elastic',revision:1}],delivery:[{revision:1}]};
const env={FALCON_CLIENT_ID:'fixture',FALCON_CLIENT_SECRET:'fixture',FALCON_CUSTOMER:'Alpha',FALCON_CLOUD:'us-2',
  NESSUS_URL:'https://fixture.invalid',NESSUS_ACCESS_KEY:'fixture',NESSUS_SECRET_KEY:'fixture',
  VULNERS_API_KEY:'fixture',SPIDERFOOT_URL:'https://fixture.invalid',ARTEMIS_API_URL:'https://fixture.invalid',ARTEMIS_API_TOKEN:'fixture',
  BURP_API_URL:'https://fixture.invalid',BURP_API_KEY:'fixture',NMAP_RUNNER_URL:'https://fixture.invalid',NMAP_RUNNER_TOKEN:'fixture',ZAP_URL:'https://fixture.invalid',ZAP_API_KEY:'fixture',
  TIDAL_EMAIL:'fixture',TIDAL_PASSWORD:'fixture',INTUNE_TENANT_ID:'tenant-intune',INTUNE_CLIENT_ID:'fixture',INTUNE_CLIENT_SECRET:'fixture',
  AUTOMATE_BASE_URL:'https://fixture.invalid',AUTOMATE_API_CLIENT_ID:'fixture',AUTOMATE_USERNAME:'fixture',AUTOMATE_PASSWORD:'fixture',
  MISP_URL:'https://fixture.invalid',MISP_API_KEY:'fixture',OPENCTI_URL:'https://fixture.invalid',OPENCTI_API_KEY:'fixture',INTELOWL_URL:'https://fixture.invalid',INTELOWL_API_KEY:'fixture',
  APPSEC_ELASTIC_URL:'https://fixture.invalid',APPSEC_ELASTIC_API_KEY:'fixture',N8N_MCP_URL:'https://fixture.invalid',
  QUALYS_API_URL:'https://fixture.invalid',QUALYS_USERNAME:'fixture',QUALYS_PASSWORD:'fixture'};
const preview=build(metadata,env);
const candidate=provider=>preview.candidates.find(c=>c.provider===provider && !['saved-tile','completed-import'].includes(c.evidence) && (provider!=='crowdstrike'||c.evidence==='environment-match'));
function binding(c,role='findings-primary',extra={}) {
  const sourceEvidence=c.evidence==='saved-tile'?preview.candidates.filter(p=>p.evidence==='shared-configuration'&&p.connectionRef===c.connectionRef&&p.provider===c.provider):[];
  const hash=createHash('sha256').update(JSON.stringify({candidate:c,sourceEvidence})).digest('hex');
  return{id:c.id,candidateHash:hash,importedHash:hash,sourcePresent:true,reviewState:'reviewed',reviewedAt:'2026-10-10',proposal:{companyId:'A',tenantId:c.tenantId??(c.provider==='crowdstrike'?'a'.repeat(32):null),datasets:role==='query-only'?['fixture-*']:[],targets:['fixture.invalid'],authority:role,...extra}};
}
test('inventory accounts for every implemented scanner and each non-scanner integration; Qualys remains planned',()=>{
  review.validatePreview(preview);
  assert.equal(Object.keys(contracts.connectorDataContracts).length,20);
  assert.deepEqual([...new Set(preview.candidates.map(c=>c.provider))].sort(),Object.keys(contracts.connectorDataContracts).sort());
  assert.equal(contracts.connectorDataContract('qualys').planned,true);
  assert.equal(candidate('qualys').capabilities.length,0);
  assert.equal(contracts.connectorDataContract('unknown'),null);
  assert.doesNotMatch(JSON.stringify(preview),/fixture.invalid|_SECRET|API_KEY|PASSWORD/);
});
for(const provider of ['defender','crowdstrike','nessus','vulners','spiderfoot','artemis','nmap','burp','zap'])test(`${provider}: reviewed findings scope remains customer-specific and rejects a stale review`,()=>{
  const c=candidate(provider),b=binding(c),result=routing.customerConnectorReadPlan('A',preview,[b]);
  assert.equal(result.bindings.length,1);assert.equal(result.canActivate,false);assert.equal(result.combinedCounts,null);
  assert.equal(routing.customerConnectorReadPlan('B',preview,[b]).bindings.length,0);
  assert.equal(routing.customerConnectorReadPlan('A',preview,[{...b,candidateHash:'0'.repeat(64)}]).bindings.length,0);
  assert.equal(routing.customerConnectorReadPlan('A',preview,[{...b,reviewState:'dismissed'}]).bindings.length,0);
});
for(const provider of ['tidal','intune','automate'])test(`${provider}: inventory role never authorizes scanner findings`,()=>{
  const c=candidate(provider);assert.deepEqual(routing.customerConnectorReadPlan('A',preview,[binding(c,'inventory')]).bindings[0].domains,['inventory']);
  assert.equal(routing.customerConnectorReadPlan('A',preview,[binding(c)]).bindings.length,0);
});
for(const provider of ['misp','opencti','intelowl'])test(`${provider}: enrichment has no endpoint finding or scan authority`,()=>{
  const c=candidate(provider),b=binding(c,'enrichment',{targets:[]});
  assert.deepEqual(routing.customerConnectorReadPlan('A',preview,[b]).bindings[0].domains,['enrichment']);
  assert.equal(routing.customerConnectorReadPlan('A',preview,[binding(c)]).bindings.length,0);
});
test('Elastic and AppSec keep query/repository scope; delivery and orchestration never become finding sources',()=>{
  for(const provider of ['elastic','appsec']) {
    const c=candidate(provider),result=routing.customerConnectorReadPlan('A',preview,[binding(c,'query-only')]);assert.equal(result.bindings.length,1);
    assert.equal(routing.customerConnectorReadPlan('A',preview,[binding(c,'query-only',{datasets:[]})]).bindings.length,0);
  }
  for(const provider of ['connectwise','n8n','qualys'])assert.equal(routing.customerConnectorReadPlan('A',preview,[binding(candidate(provider))]).bindings.length,0);
});
test('non-secret endpoint, tenant, cloud and AppSec stream changes invalidate source evidence',()=>{
  for(const [provider,key,value] of [['nessus','NESSUS_URL','https://changed.invalid'],['crowdstrike','FALCON_CLOUD','us-1'],['intune','INTUNE_TENANT_ID','tenant-other'],['appsec','APPSEC_ELASTIC_FINDING_STREAM','other-findings'],['n8n','N8N_MCP_URL','https://changed.invalid']]) {
    const changed=build(metadata,{...env,[key]:value});assert.notEqual(changed.candidates.find(c=>c.id===candidate(provider).id).revision,candidate(provider).revision);
  }
  assert.equal(build(metadata,{...env,FALCON_CLIENT_SECRET:'rotated'}).candidates.find(c=>c.id===candidate('crowdstrike').id).revision,candidate('crowdstrike').revision,'secret rotation is explicitly not claimed as revision evidence');
});

async function load(entry,overrides={}) {
  const cache=new Map(),root=resolve('lib');
  const get=path=>{path=resolve(path);assert.ok(path.startsWith(root));assert.doesNotMatch(path,/[\\/](store|persist|instrumentation)\.ts$/);
    if(!cache.has(path))cache.set(path,new SourceTextModule(ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText,{identifier:path}));return cache.get(path);};
  const m=get(resolve(root,entry+'.ts'));await m.link(async(spec,parent)=>{
    if(overrides[spec]) {const values=overrides[spec];return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v);});}
    if(spec==='./store')return new SyntheticModule(['getCompany'],function(){this.setExport('getCompany',()=>({id:'A',name:'Alpha'}));});
    if(spec==='@/lib/threat')return new SyntheticModule(['isKev'],function(){this.setExport('isKev',()=>false);});
    if(spec.startsWith('.'))return get(resolve(dirname(parent.identifier),spec+'.ts'));
    if(spec.startsWith('@/'))return get(resolve(spec.slice(2)+'.ts'));
    const values=await import(spec);return new SyntheticModule(Object.keys(values),function(){for(const [k,v]of Object.entries(values))this.setExport(k,v);});
  });await m.evaluate();return m.namespace;
}
test('all scanner records preserve existing report class, workflow exclusions and customer separation',async()=>{
  const {buildCustomerReportingModel:report}=await load('reporting-customer-model');
  const {buildCustomerCveGroups:groups}=await load('customer-cve-model');
  for(const provider of ['defender','crowdstrike','nessus','vulners','spiderfoot','artemis','nmap','burp','zap']) {
    const f={id:provider,companyId:'A',companyName:'Alpha',connector:provider,cve:'CVE-2026-1234',asset:'host-a',status:'Open',severity:'High',cvss:8.1,realRisk:65,remediation:'Install recommended update',assetSource:'inferred',lastSeen:'2026-10-10',title:'Fixture'};
    const result=report({id:'A',name:'Alpha'},[f,{...f,id:'other',companyId:'B'}],[],[],[]);
    const domain=contracts.connectorFindingClass(provider);
    assert.equal(result.metrics.vulnerabilities.open,domain==='osint'?0:1);assert.equal(result.metrics.attackSurface.open,domain==='osint'?1:0);
    assert.equal(report({id:'A',name:'Alpha'},[{...f,status:'Risk Accepted'}],[],[],[]).metrics.vulnerabilities.open,0);
    if(domain!=='osint') {const packets=groups({id:'A',name:'Alpha'},f.cve,[f],[],new Set(),'2026-10-10');assert.equal(packets.length,1);assert.match(packets[0].csv,/host-a/);assert.ok(packets[0].manualOnly);assert.doesNotMatch(packets[0].ticketBody,/host-a/);}
  }
});
test('Burp, Nmap, Artemis and Tidal actual import parsers preserve native non-CVE and inventory evidence',async()=>{
  const burp=await load('burp'),nmap=await load('nmap'),artemis=await load('artemis'),tidal=await load('tidal'),zap=await load('zap');
  const issue=burp.parseBurpXml('<issues><issue><type>123</type><host>https://app.fixture.invalid</host><path>/login</path><severity>High</severity><name>SQL injection</name><remediationBackground>Use bound parameters</remediationBackground></issue></issues>')[0];
  assert.equal(issue.cve,'BURP-123');assert.equal(issue.path,'/login');assert.equal(issue.remediation,'Use bound parameters');
  const host=nmap.parseNmapXml('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><hostnames><hostname name="host-a"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>')[0];
  assert.equal(host.ports.length,2);assert.equal(nmap.nmapServiceFindings(host).length,1);assert.match(nmap.nmapServiceFindings(host)[0].cve,/^NMAP-/);
  const exposure=artemis.mapArtemisResult({target:'app.fixture.invalid',headline:'Exposed administration page',receiver:'admin',severity:'high',tag:'Alpha'});assert.equal(exposure.cve,'ARTEMIS-ADMIN');assert.equal(exposure.tag,'Alpha');
  const asset=tidal.parseTidalCsv('id,hostname,customer,ip,criticality\nasset-1,host-a,Alpha,10.0.0.1,high')[0];assert.equal(asset.externalId,'asset-1');assert.equal(asset.customer,'Alpha');assert.deepEqual(asset.ipAddresses,['10.0.0.1']);
  assert.equal(zap.zapMapRiskToSeverity('3'),'High');
});

test('Intune imports complete inventory pages and refuses unsafe links, malformed pages and truncated results',async()=>{
  const intune=await load('intune'),fetchBefore=globalThis.fetch;
  const keys=['INTUNE_TENANT_ID','INTUNE_CLIENT_ID','INTUNE_CLIENT_SECRET'],before=keys.map(k=>process.env[k]);
  keys.forEach(k=>process.env[k]='fixture');
  let pages=[],calls=[];
  globalThis.fetch=async(url,options)=>{
    calls.push(String(url));
    if(String(url).startsWith('https://login.microsoftonline.com/'))return Response.json({access_token:'fixture-token'});
    assert.equal(new URL(url).origin,'https://graph.microsoft.com');assert.equal(options.redirect,'error');
    assert.equal(options.headers.Authorization,'Bearer fixture-token');
    return Response.json(pages.shift());
  };
  const next='https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=fixture';
  try {
    pages=[{value:[{id:'device-1',deviceName:'first',operatingSystem:'Windows Server',userPrincipalName:'owner',complianceState:'compliant'}],'@odata.nextLink':next},{value:[{id:'device-2',deviceName:'second',operatingSystem:'Android',managedDeviceOwnerType:'personal'}]}];
    const assets=await intune.intuneListAssets();assert.equal(assets.length,2);assert.equal(assets[0].criticality,'High');assert.equal(assets[1].criticality,'Low');assert.equal(assets[0].externalId,'device-1');assert.deepEqual(assets[0].ipAddresses,[]);
    pages=[{value:[],'@odata.nextLink':'https://attacker.invalid/collect'}];calls=[];
    await assert.rejects(()=>intune.intuneListAssets(),/unexpected.*pagination/);assert.equal(calls.length,2);
    pages=[{error:'invalid'}];await assert.rejects(()=>intune.intuneListAssets(),/invalid inventory page/);
    pages=Array.from({length:100},()=>({value:[],'@odata.nextLink':next}));
    await assert.rejects(()=>intune.intuneListAssets(),/pagination limit/);
  }finally{globalThis.fetch=fetchBefore;keys.forEach((k,i)=>before[i]===undefined?delete process.env[k]:process.env[k]=before[i]);}
});

test('Automate preserves customer filters and inventory identity; incomplete or cross-customer responses cannot publish',async()=>{
  const automate=await load('connectwise-automate'),fetchBefore=globalThis.fetch;
  const config={baseUrl:'https://fixture.invalid/api',apiClientId:'fixture',username:'fixture',password:'fixture'};
  let pages=[],calls=[];
  globalThis.fetch=async(url,options)=>{
    calls.push(String(url));if(String(url).endsWith('/apitoken'))return Response.json({AccessToken:'fixture-token'});
    assert.equal(options.headers.Authorization,'Bearer fixture-token');
    if(String(url).includes('/computers?'))assert.equal(new URL(url).searchParams.get('condition'),'Client/Id=98');
    return Response.json(pages.shift());
  };
  const device={Id:1,ComputerName:'host-a',Client:{Id:98},OperatingSystemName:'Windows',Type:'Server',LocalIPAddress:'10.0.0.1',LastUserName:'DOMAIN\\owner'};
  try {
    pages=[Array.from({length:250},(_,i)=>({...device,Id:i+1})),[{...device,Id:251}]];
    const assets=await automate.automateListComputers(config,'98');assert.equal(assets.length,251);assert.equal(assets[0].externalId,'automate:1');assert.equal(assets[0].owner,'owner');assert.equal(assets[0].criticality,'High');assert.deepEqual(assets[0].ipAddresses,['10.0.0.1']);
    calls=[];await assert.rejects(()=>automate.automateListComputers(config,'98 OR 1=1'),/valid Automate customer/);assert.equal(calls.length,0);
    pages=[[{...device,Client:{Id:99}}]];await assert.rejects(()=>automate.automateListComputers(config,'98'),/different customer/);
    pages=[{error:'invalid'}];await assert.rejects(()=>automate.automateListComputers(config,'98'),/invalid computers page/);
    pages=[{error:'invalid'}];await assert.rejects(()=>automate.automateListClients(config),/invalid clients page/);
    pages=Array.from({length:200},()=>Array.from({length:250},()=>device));await assert.rejects(()=>automate.automateListComputers(config,'98'),/pagination limit/);
    pages=Array.from({length:200},()=>Array.from({length:250},()=>({Id:98,Name:'Fixture'})));await assert.rejects(()=>automate.automateListClients(config),/pagination limit/);
    pages=[[{Id:98,Name:'Fixture'}]];assert.deepEqual(await automate.automateListClients(config),[{id:'98',name:'Fixture'}]);
  }finally{globalThis.fetch=fetchBefore;}
});

test('Nessus, SpiderFoot and ZAP import fixtures preserve scan coverage and reject malformed success bodies',async()=>{
  let replies=new Map();const calls=[];
  const server=createServer((req,res)=>{calls.push(req.method);res.setHeader('Content-Type','application/json');
    const path=new URL(req.url,'http://localhost').pathname;res.end(JSON.stringify(replies.get(path)??{error:'unexpected request'}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const base='http://127.0.0.1:'+server.address().port;
  const vars={NESSUS_URL:base,NESSUS_ACCESS_KEY:'fixture',NESSUS_SECRET_KEY:'fixture',SPIDERFOOT_URL:base,ZAP_URL:base,ZAP_API_KEY:'fixture',ARTEMIS_API_URL:base,ARTEMIS_API_TOKEN:'fixture'};
  const before=Object.fromEntries(Object.keys(vars).map(k=>[k,process.env[k]]));Object.assign(process.env,vars);
  try {
    const nessus=await load('nessus'),spider=await load('spiderfoot'),zap=await load('zap'),artemis=await load('artemis');
    replies=new Map([
      ['/scans/1',{hosts:[{host_id:1,hostname:'host-a'},{host_id:2,hostname:'host-clean'}]}],
      ['/scans/1/hosts/1',{info:{'host-fqdn':'host-a','host-ip':'10.0.0.1'},vulnerabilities:[{plugin_id:100,severity:4,plugin_name:'Fixture plugin'}]}],
      ['/scans/1/hosts/2',{info:{'host-fqdn':'host-clean'},vulnerabilities:[]}],
      ['/scans/1/hosts/1/plugins/100',{info:{plugindescription:{pluginattributes:{cve:['CVE-2026-1234','CVE-2026-1235'],solution:'Install fix',risk_information:{cvss3_base_score:'9.8'}}}},outputs:[{ports:{'443 / tcp':[]}}]}]
    ]);
    const scan=await nessus.nessusImportFindings(1);assert.equal(scan.scannedHosts.length,2);assert.equal(scan.findings.length,1);assert.deepEqual(scan.findings[0].cves,['CVE-2026-1234','CVE-2026-1235']);assert.equal(scan.findings[0].remediation,'Install fix');assert.equal(scan.findings[0].port,'443');
    replies.set('/scans/1/hosts/2',{});await assert.rejects(()=>nessus.nessusImportFindings(1),/invalid host vulnerability/);
    replies.set('/scans/1',{});await assert.rejects(()=>nessus.nessusImportFindings(1),/invalid scan host/);
    replies.set('/scanexportjsonmulti',[
      {event_type:'VULNERABILITY_CVE_HIGH',data:'CVE-2026-1234 exposed',source_data:'host-a',scan_target:'alpha.fixture.test'},
      {event_type:'VULNERABILITY_CVE_HIGH',data:'Ignored false positive',false_positive:'1'},
      {event_type:'INTERNET_NAME',data:'Informational'}]);
    const exposures=await spider.spiderfootImportFindings('fixture');assert.equal(exposures.length,1);assert.equal(exposures[0].asset,'host-a');assert.equal(exposures[0].cve,'CVE-2026-1234');
    replies.set('/scanexportjsonmulti',{});await assert.rejects(()=>spider.spiderfootImportFindings('fixture'),/invalid scan event/);
    replies.set('/OTHER/core/other/jsonreport/',{site:[{'@name':'https://alpha.fixture.test',alerts:[{name:'SQL injection',riskcode:'3',cweid:'89',solution:'Use bound parameters',instances:[{uri:'/a'},{uri:'/b'}]}]}]});
    const findings=await zap.zapFetchReport();assert.equal(findings.length,1);assert.equal(findings[0].cve,'ZAP-89');assert.equal(findings[0].severity,'High');assert.match(findings[0].description,/2 instances/);
    replies.set('/OTHER/core/other/jsonreport/',{});await assert.rejects(()=>zap.zapFetchReport(),/invalid report site/);
    replies.set('/api/analyses',{});assert.equal((await artemis.artemisStatus()).ready,false);await assert.rejects(()=>artemis.artemisListAnalyses(),/invalid analysis/);
    replies.set('/api/task-results',{});await assert.rejects(()=>artemis.artemisImportFindings(),/invalid task/);
    replies.set('/api/task-results',Array.from({length:200},()=>({target:'host-a',headline:'Exposure',severity:'high'})));
    await assert.rejects(()=>artemis.artemisImportFindings(),/pagination limit/);
    assert.ok(calls.length>0&&calls.every(v=>v==='GET'),'fixtures never launch scans');
  }finally{for(const[k,v]of Object.entries(before))v===undefined?delete process.env[k]:process.env[k]=v;server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});

test('Tidal company sessions stay separate and partial inventories or roster failures are reported',async()=>{
  const tidal=await load('tidal'),fetchBefore=globalThis.fetch,errorBefore=console.error;
  const vars={TIDAL_EMAIL:'fixture',TIDAL_PASSWORD:'fixture',TIDAL_API_URL:'https://fixture.invalid'},before=Object.fromEntries(Object.keys(vars).map(k=>[k,process.env[k]]));
  Object.assign(process.env,vars);console.error=()=>{};
  let mode='ok',company=null,deviceCalls=[];
  globalThis.fetch=async(raw,options={})=>{
    const url=new URL(raw),path=url.pathname;
    if(path==='/auth/csrf-cookie')return new Response('',{headers:{'set-cookie':'XSRF-TOKEN=fixture; Path=/'}});
    if(path==='/auth/login')return Response.json({ok:true});
    if(path==='/api/v1/admin/companies') {
      if(mode==='roster-error'&&url.searchParams.has('page'))return new Response('',{status:503});
      return Response.json({data:[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}],...(mode==='roster-error'?{pagination:{has_next:true,links:{next:'https://fixture.invalid/api/v1/admin/companies?page=2'}}}: {})});
    }
    if(path.endsWith('/switch-company')){const next=JSON.parse(options.body).company_id;if(mode==='switch-error'&&next==='B')return new Response('',{status:403});company=next;return Response.json({ok:true});}
    if(path.endsWith('/auvik/tenants'))return Response.json([]);
    if(path.endsWith('/intune/devices')){
      deviceCalls.push(company);
      if(company==='B'&&mode==='malformed')return Response.json({error:'wrong shape'});
      if(company==='B'&&mode==='partial'&&url.searchParams.has('page'))return new Response('',{status:403});
      const more=company==='B'&&['partial','capped'].includes(mode);
      return Response.json({data:[{device_id:'device-'+company,device_name:'host-'+company}],pagination:{has_next:more,...(more?{links:{next:'https://fixture.invalid'+path+'?page=2'}}:{})}});
    }
    if(path.endsWith('/devices'))return new Response('',{status:404});
    throw new Error('Unexpected fixture request');
  };
  try {
    let result=await tidal.tidalListAssets();assert.deepEqual(result.assets.map(a=>a.customer),['Alpha','Beta']);assert.equal(result.errors.length,0);
    for(mode of ['malformed','partial','capped','switch-error']) {
      deviceCalls=[];result=await tidal.tidalListAssets();assert.deepEqual(result.assets.map(a=>a.customer),['Alpha']);assert.equal(result.errors.length,1);assert.match(result.errors[0],/^Beta:/);
      if(mode==='switch-error')assert.ok(!deviceCalls.includes('B'));
    }
    mode='roster-error';deviceCalls=[];await assert.rejects(()=>tidal.tidalListAssets(),/company roster failed/);assert.deepEqual(deviceCalls,[]);
  }finally{globalThis.fetch=fetchBefore;console.error=errorBefore;for(const[k,v]of Object.entries(before))v===undefined?delete process.env[k]:process.env[k]=v;}
});

test('AppSec keeps repository metrics and scan deltas separate; incomplete result schemas fail explicitly',async()=>{
  const before=Object.fromEntries(['APPSEC_ELASTIC_URL','APPSEC_ELASTIC_API_KEY'].map(k=>[k,process.env[k]]));
  Object.assign(process.env,{APPSEC_ELASTIC_URL:'https://fixture.invalid',APPSEC_ELASTIC_API_KEY:'fixture'});
  let response,queries=[];
  const query=async(connection,sql)=>{assert.equal(connection.apiKey,'fixture');queries.push(sql);return response;};
  const result=(names,rows)=>({columns:names.split(',').map(name=>({name,type:'keyword'})),rows});
  try {
    const appsec=await load('elastic-appsec',{'./elastic-query-client':{executeEsql:query},'./customer-elastic-query':{executeCustomerEsql:()=>{throw Error('Unexpected reviewed query');}}});
    response=result('repository,last_scan,findings,vulnerabilities,misconfigurations,licenses,critical,high,medium,low,secrets,new_findings,new_critical,new_high,resolved,gate',[
      ['repo-a','2026-10-10',10,7,2,1,1,3,4,2,0,2,1,1,3,'fail'],
      ['repo-b','2026-10-10',5,3,1,1,0,1,2,2,1,1,0,0,2,'pass']]);
    const summary=await appsec.fetchAppSecSummary();assert.equal(summary.repositories,2);assert.equal(summary.findings,15);assert.equal(summary.vulnerabilities,10);assert.equal(summary.resolved,5);assert.equal(summary.rows[0].repository,'repo-a');
    response=result('day,critical,high,resolved',[['2026-10-10',1,4,5]]);
    assert.deepEqual(await appsec.fetchAppSecTrend(),[{completedAt:'2026-10-10',critical:1,high:4,resolved:5}]);
    assert.match(queries[1],/LATEST/);assert.match(queries[1],/SUM\(`gmi.appsec.delta.resolved.total`\)/);
    response=result('repository',[['repo-a']]);await assert.rejects(()=>appsec.fetchAppSecSummary(),/missing.*column/);
  }finally{for(const[k,v]of Object.entries(before))v===undefined?delete process.env[k]:process.env[k]=v;}
});


test('reviewed Nessus transport scopes requests, rejects changed/foreign results and verifies the folder before launching',async()=>{
 const calls=[],bodies=[];let mode='valid',rosterReads=0;
 const server=createServer((req,res)=>{let text='';req.on('data',chunk=>text+=chunk);req.on('end',()=>{
  calls.push({method:req.method,url:req.url});if(text)bodies.push(JSON.parse(text));res.setHeader('Content-Type','application/json');
  let body={error:'Unexpected fixture request'};
  if(req.url==='/folders')body={folders:[{id:17,name:'Fixture',type:'custom'}]};
  if(req.url==='/scans?folder_id=17'){rosterReads++;body={scans:mode==='missing'?[]:[{id:1,folder_id:mode==='foreign'?18:17,status:'completed',last_modification_date:mode==='changed'&&rosterReads>1?200:100}]};}
  if(req.url==='/scans/1')body={info:{status:mode==='running'?'running':'completed'},hosts:[{host_id:1,hostname:'host-a'},...(mode==='duplicate'?[{host_id:1,hostname:'host-a'}]:[])]};
  if(req.url==='/scans/1/hosts/1')body={info:{'host-fqdn':'host-a','host-ip':mode==='outside'?'10.1.0.1':'10.0.0.1'},vulnerabilities:[]};
  if(req.url==='/editor/scan/templates')body={templates:[{uuid:'fixture',name:'basic'}]};
  if(req.url==='/scans'&&req.method==='POST')body={scan:{id:1}};
  if(req.url==='/scans/1/launch')body={scan_uuid:'fixture'};
  res.end(JSON.stringify(body));
 });});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const nessus=await load('nessus'),config={url:'http://127.0.0.1:'+server.address().port,accessKey:'fixture',secretKey:'fixture',insecure:false};
  const scope={config,folderId:17,targets:['10.0.0.0/24'],lastModified:100};
  assert.equal((await nessus.nessusImportFindings(1,500,scope)).scannedHosts.length,1);
  for(mode of ['foreign','outside','running','duplicate','changed','missing']){rosterReads=0;await assert.rejects(()=>nessus.nessusImportFindings(1,500,scope));}
  mode='valid';rosterReads=0;assert.equal((await nessus.nessusLaunchScan('Fixture',['10.0.0.1'],'standard',scope)).nessusScanId,1);
  assert.equal(bodies.at(-1).settings.folder_id,17);assert.equal(bodies.at(-1).settings.enabled,false);
  const launched=calls.filter(c=>c.url.endsWith('/launch')).length;
  mode='missing';await assert.rejects(()=>nessus.nessusLaunchScan('Fixture',['10.0.0.1'],'standard',scope),/not launched/);
  assert.equal(calls.filter(c=>c.url.endsWith('/launch')).length,launched);
  const before=calls.length;await assert.rejects(()=>nessus.nessusLaunchScan('Fixture',['10.0.1.1'],'standard',scope),/exceed/);assert.equal(calls.length,before);
  assert.ok(calls.every(c=>c.url!=='/scans'||c.method==='POST'));
 }finally{await new Promise(r=>server.close(r));}
});

test('reviewed SpiderFoot transport verifies finished scan identity and every exported event before mapping',async()=>{
 const calls=[];let mode='valid',rosterReads=0;
 const server=createServer((req,res)=>{calls.push(req.url);const url=new URL(req.url,'http://fixture');res.setHeader('Content-Type','application/json');let data;
  if(url.pathname==='/scanlist'){
   rosterReads++;data=[['scan-1','Fixture','acme.example','created','started',mode==='changed'&&rosterReads>1?'changed':'finished',mode==='unfinished'?'UNFINISHED':'FINISHED',2,{}]];
   if(mode==='duplicate')data.push(data[0]);if(mode==='malformed')data={error:'bad'};
  }else if(url.pathname==='/scanexportjsonmulti'){
   assert.equal(url.searchParams.get('ids'),'scan-1');data=[{event_type:'VULNERABILITY_CVE_HIGH',data:'CVE-2026-1234',source_data:'related.external.example',scan_target:'acme.example',scan_name:'Fixture'}];
   if(mode==='foreign')data.push({event_type:'IGNORED_INFO',scan_target:'another.example',scan_name:'Fixture'});
   if(mode==='missing')delete data[0].scan_target;if(mode==='wrong-name')data[0].scan_name='Foreign';
  }else if(url.pathname==='/startscan')data=['SUCCESS','started-1'];
  else throw Error('Unexpected request');res.end(JSON.stringify(data));
 });await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const spider=await load('spiderfoot'),config={url:'http://127.0.0.1:'+server.address().port,auth:null,insecure:false};
  const scan=(await spider.spiderfootListScans(config))[0],scope={config,scan,targets:['acme.example']};rosterReads=0;
  const findings=await spider.spiderfootImportFindings('scan-1',scope);assert.equal(findings.length,1);assert.equal(findings[0].asset,'related.external.example');
  for(mode of ['foreign','missing','wrong-name','duplicate','malformed','changed','unfinished']){rosterReads=0;await assert.rejects(()=>spider.spiderfootImportFindings('scan-1',scope));}
  mode='valid';let before=calls.length;await assert.rejects(()=>spider.spiderfootStartScan('Fixture','another.example','Footprint',scope),/outside/);assert.equal(calls.length,before);
  assert.equal(await spider.spiderfootStartScan('Fixture','ACME.example.','Footprint',scope),'started-1');
 }finally{await new Promise(r=>server.close(r));}
});
test('reviewed Artemis transport filters exact tag and analysis ID, rejects mixed/incomplete pages and validates launches',async()=>{
 const calls=[],bodies=[];let mode='valid',rosterReads=0;
 const server=createServer((req,res)=>{let body='';req.on('data',d=>body+=d);req.on('end',()=>{
  const url=new URL(req.url,'http://fixture');calls.push(req.url);res.setHeader('Content-Type','application/json');let data;
  if(url.pathname==='/api/analyses'){
   assert.equal(url.searchParams.get('tag'),'ExactTag');rosterReads++;
   data=[{id:'analysis-1',tag:mode==='wrong-tag'?'Other':'ExactTag',target:mode==='foreign-target'?'other.example':'acme.example',stopped:false,num_pending_tasks:mode==='pending'||mode==='changed'&&rosterReads>1?1:0}];
   if(mode==='duplicate-analysis')data.push(data[0]);if(mode==='missing-pending')delete data[0].num_pending_tasks;
  }else if(url.pathname==='/api/task-results'){
   assert.equal(url.searchParams.get('analysis_id'),'analysis-1');assert.equal(url.searchParams.get('only_interesting'),'true');
   const row={id:'result-1',analysis_id:mode==='foreign-analysis'?'other':'analysis-1',tag:mode==='foreign-tag'?'Other':'ExactTag',target_string:'related.external.example',receiver:'nuclei',status_reason:'CVE-2026-1234'};
   data=[row];if(mode==='missing-id')delete row.id;
   if(mode==='duplicate-results')data=[row,row];
   if(mode==='limit')data=Array.from({length:200},(_,i)=>({...row,id:url.searchParams.get('page')+'-'+i}));
  }else if(url.pathname==='/api/add'){bodies.push(JSON.parse(body));data={ok:true,ids:mode==='bad-launch'?[]:['created-1']};}
  else throw Error('Unexpected request');res.end(JSON.stringify(data));
 });});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const ar=await load('artemis'),config={url:'http://127.0.0.1:'+server.address().port,token:'fixture'},scope={config,tag:'ExactTag',targets:['acme.example']};
  const findings=await ar.artemisImportFindings(scope);assert.equal(findings.length,1);assert.equal(findings[0].asset,'related.external.example');
  for(mode of ['wrong-tag','foreign-target','duplicate-analysis','missing-pending','foreign-analysis','foreign-tag','missing-id','duplicate-results','changed','limit']){rosterReads=0;await assert.rejects(()=>ar.artemisImportFindings(scope));}
  mode='pending';rosterReads=0;let count=calls.filter(c=>c.startsWith('/api/task-results')).length;assert.deepEqual(await ar.artemisCollectReviewedFindings(scope),{findings:[],incompleteAnalyses:1});assert.equal(calls.filter(c=>c.startsWith('/api/task-results')).length,count);
  mode='valid';count=calls.length;await assert.rejects(()=>ar.artemisAddTargets(['foreign.example'],'ExactTag',scope),/exceeds/);await assert.rejects(()=>ar.artemisAddTargets(['acme.example'],'Other',scope),/exceeds/);assert.equal(calls.length,count);
  assert.equal((await ar.artemisAddTargets(['acme.example'],'ExactTag',scope)).ok,true);assert.deepEqual(bodies.at(-1),{targets:['acme.example'],tag:'ExactTag'});
  mode='bad-launch';await assert.rejects(()=>ar.artemisAddTargets(['acme.example'],'ExactTag',scope),/inspect the scanner/);
 }finally{await new Promise(r=>server.close(r));}
});


test('reviewed ZAP uses a private origin context, gateway authentication and strict report evidence',async()=>{
 const zap=await load('zap'),before=globalThis.fetch,calls=[];
 const config={baseUrl:'https://zap.fixture.invalid',apiKey:'fixture-key'};
 const own={"@name":'https://app.example',alerts:[{riskcode:'3',cweid:'79',name:'XSS',desc:'Test',solution:'Encode',instances:[{uri:'https://app.example/login'}]}]};
 let report={site:[{...own,"@name":'https://app.example.evil'},own]},status='100';
 globalThis.fetch=async(url,options)=>{
  url=new URL(url);calls.push(url);assert.equal(url.origin,config.baseUrl);assert.equal(url.searchParams.get('apikey'),config.apiKey);assert.equal(options.headers.Host,'zap');assert.equal(options.redirect,'error');
  if(url.pathname.includes('newContext'))return Response.json({contextId:'1'});
  if(url.pathname.includes('includeInContext')||url.pathname.includes('removeContext'))return Response.json({Result:'OK'});
  if(url.pathname.includes('/action/scan/'))return Response.json({scan:'2'});
  if(url.pathname.includes('/view/status/'))return Response.json({status});
  if(url.pathname.includes('jsonreport'))return Response.json(report);
  assert.fail('Unexpected ZAP endpoint '+url.pathname);
 };
 try{
  const scope=await zap.zapCreateScope(config,'https://app.example');
  const regex=new RegExp(calls.find(c=>c.pathname.includes('includeInContext')).searchParams.get('regex'));
  assert.ok(regex.test('https://app.example/path'));for(const v of ['https://app.example.evil','https://appXexample','http://app.example','https://app.example:8443'])assert.equal(regex.test(v),false);
  await zap.zapStartSpider('https://app.example',scope);await zap.zapStartActiveScan('https://app.example',scope);
  assert.equal(calls.find(c=>c.pathname.includes('/spider/action/scan')).searchParams.get('contextName'),scope.name);
  assert.equal(calls.find(c=>c.pathname.includes('/ascan/action/scan')).searchParams.get('contextId'),scope.id);
  const count=calls.length;await assert.rejects(()=>zap.zapStartSpider('https://other.example',scope),/outside/);assert.equal(calls.length,count);
  const results=await zap.zapFetchReport(scope);assert.equal(results.length,1);assert.equal(results[0].cve,'ZAP-79');assert.match(results[0].description,/Retained ZAP session/);
  report={site:[{...own,alerts:[{...own.alerts[0],instances:[{uri:'https://app.example.evil/x'}]}]}]};await assert.rejects(()=>zap.zapFetchReport(scope),/outside/);
  report={site:[]};await assert.rejects(()=>zap.zapFetchReport(scope),/coverage is unknown/);
  for(const value of [null,'',101,-1,'unknown',100.5]){status=value;await assert.rejects(()=>zap.zapSpiderStatus('2',config),/malformed/);await assert.rejects(()=>zap.zapActiveScanStatus('2',config),/malformed/);}
  await zap.zapRemoveScope(scope);
 }finally{globalThis.fetch=before;}
});

test('reviewed bridge keeps deployment credentials together and rejects foreign or incomplete job evidence',async()=>{
 const bridge=await load('vulners'),before=globalThis.fetch;
 const keys=['GMI_SCANNER_URL','GMI_SCANNER_API_KEY','VULNERS_BRIDGE_URL','VULNERS_BRIDGE_API_KEY'],prior=keys.map(k=>process.env[k]);
 const config={baseUrl:'https://bridge.fixture.invalid',apiKey:'fixture-key'},scope={config,target:'10.0.0.1'};
 let calls=[],job={id:'job-1',status:'Done'},data={findings:[{host:'10.0.0.1',cves:['CVE-2026-1234'],severity:8,name:'Service',port:'443/tcp'}]};
 globalThis.fetch=async(url,options)=>{
  calls.push([url,options]);assert.equal(new URL(url).origin,config.baseUrl);assert.equal(options.headers['X-API-Key'],config.apiKey);assert.equal(options.redirect,'error');
  if(url.endsWith('/start'))return Response.json({id:'job-1',status:'Requested'});
  if(options.method==='POST')return Response.json({task_id:'job-1'});
  return Response.json(url.endsWith('/findings')?data:job);
 };
 try{
  process.env.GMI_SCANNER_URL='https://preferred.invalid';delete process.env.GMI_SCANNER_API_KEY;
  process.env.VULNERS_BRIDGE_URL='https://fallback.invalid/api';process.env.VULNERS_BRIDGE_API_KEY='fallback';
  assert.deepEqual(bridge.vulnersBridgeConfig(),{baseUrl:'https://fallback.invalid',apiKey:'fallback'});
  delete process.env.VULNERS_BRIDGE_URL;assert.equal(bridge.vulnersBridgeConfig(),null);
  assert.equal((await bridge.vulnersBridgeStartScan('10.0.0.1','Fixture',scope)).jobId,'job-1');
  assert.deepEqual(JSON.parse(calls[0][1].body).hosts,['10.0.0.1']);assert.equal(JSON.parse(calls[1][1].body).authorization_confirmed,true);
  calls=[];await assert.rejects(()=>bridge.vulnersBridgeStartScan('10.0.0.2','Fixture',scope),/outside/);assert.equal(calls.length,0);
  await assert.rejects(()=>bridge.vulnersBridgeStartScan('10.0.0.1','Fixture',{...scope,verify:async()=>{throw Error('revoked');}}),/revoked/);assert.equal(calls.length,1,'no start request after approval revocation');
  assert.equal((await bridge.vulnersBridgeJobStatus('job-1',scope)).status,'complete');
  job={id:'other',status:'Done'};await assert.rejects(()=>bridge.vulnersBridgeJobStatus('job-1',scope),/identity/);
  const results=await bridge.vulnersBridgeJobFindings('job-1','10.0.0.1',scope);assert.equal(results.length,1);assert.equal(results[0].cvss,8);
  const good=structuredClone(data);
  for(const bad of [{},{findings:null},{...good,total:2},{...good,has_more:true},
    {findings:[{...good.findings[0],host:'10.0.0.2'}]},{findings:[{...good.findings[0],host:null}]},
    {findings:[{...good.findings[0],cves:undefined}]},{findings:[{...good.findings[0],cves:['invalid']}]},
    {findings:[{...good.findings[0],severity:'NaN'}]}]){
   data=bad;await assert.rejects(()=>bridge.vulnersBridgeJobFindings('job-1','10.0.0.1',scope));
  }
  data={findings:[]};assert.deepEqual(await bridge.vulnersBridgeJobFindings('job-1','10.0.0.1',scope),[]);
 }finally{globalThis.fetch=before;keys.forEach((k,i)=>prior[i]===undefined?delete process.env[k]:process.env[k]=prior[i]);}
});
