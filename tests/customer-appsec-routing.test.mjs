import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';
import { loadConnectorPreview, loadConnectorReview, loadAppSecRouting, loadElasticScope, loadConnectorStatus } from '../scripts/connector-preview-loader.mjs';
const build = await loadConnectorPreview(), review = await loadConnectorReview(), policy = await loadAppSecRouting();
const env = { APPSEC_ELASTIC_URL: 'https://fixture.invalid', APPSEC_ELASTIC_API_KEY: 'fixture' };
const metadata = { companies: [{id:'A',name:'Alpha'},{id:'B',name:'Beta'},{id:'DEMO',name:'Demo',isDemo:true}], defender:[], spotlight:[], connections:[], tiles:[] };
const elasticScope = await loadElasticScope();
const preview = build(metadata,env), candidate = preview.candidates.find(c=>c.provider==='appsec');
const hash = review.connectorDraftEvidence(candidate,preview.candidates).candidateHash;
const proposal = { companyId:'A',tenantId:null,authority:'query-only',targets:['Acme/Alpha'],datasets:['gmi-appsec-scans','gmi-appsec-findings'] };
const row = {candidate_id:candidate.id,company_id:'A',provider:'appsec',source_scope:'["acme/alpha"]',candidate_hash:hash,binding_hash:hash,imported_hash:hash,
  binding_revision:1,current_binding_revision:1,revision:1,enabled:true,source_present:true,review_state:'reviewed',reviewed_at:'2026-10-10',proposal};
class DashboardError extends Error { constructor(message,status=400) {super(message);this.status=status;} }
async function load(entry,overrides={}) {
  const cache=new Map();
  const get=path=>{path=resolve(path);assert.ok(path.startsWith(resolve('.')));assert.doesNotMatch(path,/[\\/](store|persist|instrumentation)\.ts$/);
    if(!cache.has(path))cache.set(path,new SourceTextModule(ts.transpileModule(readFileSync(path,'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText,{identifier:path}));return cache.get(path);};
  const m=get(entry);await m.link(async(spec,parent)=>{
    if(overrides[spec]) {const values=overrides[spec];return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v);});}
    if(spec.startsWith('.'))return get(resolve(dirname(parent.identifier),spec+'.ts'));
    if(spec.startsWith('@/'))return get(resolve(spec.slice(2)+'.ts'));
    assert.ok(spec.startsWith('node:'),'Unexpected dependency '+spec);
    const values=await import(spec);return new SyntheticModule(Object.keys(values),function(){for(const[k,v]of Object.entries(values))this.setExport(k,v);});
  });await m.evaluate();return m.namespace;
}
async function withEnv(extra,fn) {
  const values={...env,VULN_REVIEWED_APPSEC_PROVIDERS:'appsec',...extra};
  const before=Object.fromEntries(Object.keys(values).map(k=>[k,process.env[k]]));Object.assign(process.env,values);
  try {return await fn();}finally{for(const[k,v]of Object.entries(before))v===undefined?delete process.env[k]:process.env[k]=v;}
}
const result=(names,rows,extra={})=>({columns:names.split(',').map(name=>({name,type:'keyword'})),rows,...extra});
const summaryNames='repository,last_scan,findings,vulnerabilities,misconfigurations,licenses,critical,high,medium,low,secrets,new_findings,new_critical,new_high,resolved,gate';
const summaryRow=['Acme/Alpha','2026-10-10',10,7,2,1,1,3,4,2,0,2,1,1,3,'fail'];
const scope={connection:{endpoint:env.APPSEC_ELASTIC_URL,apiKey:'fixture'},repositories:['Acme/Alpha','Acme/Other'],streams:policy.appsecStreams(env)};

test('AppSec approval requires explicit opt-in, configured exact streams and qualified unique repository ownership',()=>{
  assert.equal(policy.reviewedAppSecRouting(),false);assert.equal(policy.reviewedAppSecRouting('appsec'),true);
  for(const s of ['all','true','appsec,','elastic'])assert.throws(()=>policy.reviewedAppSecRouting(s));
  assert.equal(policy.appsecBindingScope('A',preview,row,env).sourceScope,'["acme/alpha"]');
  for(const targets of [[],['repo'],['*/repo'],['acme/repo','ACME/Repo'],['acme/..'],['acme/a"|FROM other']])
    assert.throws(()=>policy.appsecBindingScope('A',preview,{...row,proposal:{...proposal,targets}},env));
  for(const edit of [{tenantId:'tenant'},{authority:'findings-primary'},{datasets:['other']},{datasets:['gmi-appsec-*']}])
    assert.throws(()=>policy.appsecBindingScope('A',preview,{...row,proposal:{...proposal,...edit}},env));
  for(const edit of [{source_present:false},{review_state:'pending-review'},{imported_hash:'0'.repeat(64)}])assert.throws(()=>policy.appsecBindingScope('A',preview,{...row,...edit},env));
  assert.throws(()=>policy.appsecBindingScope('A',build(metadata,{...env,APPSEC_ELASTIC_URL:'https://changed.invalid'}),row,env));
});

test('AppSec status is scoped and does not expose repository identities, keys or stream names',async()=>{
  const project=await loadConnectorStatus(),draft={id:candidate.id,candidate,candidate_hash:hash,proposal,source_present:true,review_state:'reviewed',reviewed_at:row.reviewed_at};
  const status=policy.appsecRoutingStatus(row,preview,{...env,VULN_REVIEWED_APPSEC_PROVIDERS:'appsec'});
  const value=project('A',preview,[draft],true,undefined,[],[],[],[],[status]);assert.equal(value.items[0].review,'AppSec route approved');
  assert.doesNotMatch(JSON.stringify(value),/Acme|gmi-appsec|fixture.invalid|source_scope/);
  assert.equal(project('B',preview,[draft],true,undefined,[],[],[],[],[status]).items.length,0);
  assert.match(policy.appsecRoutingStatus({...row,current_binding_revision:2},preview,env).review,/needs review/);
});

test('summary and trend filter repository identities before aggregation and use the approved coverage denominator',async()=>withEnv({},async()=>{
  const calls=[];let response=result(summaryNames,[summaryRow]);
  const app=await load('lib/elastic-appsec.ts',{'./elastic-dashboard':{DashboardError},'./elastic-query-client':{executeEsql:()=>{throw Error('Legacy query');}},
    './customer-elastic-query':{executeCustomerEsql:async(connection,sql,background,datasets)=>{assert.deepEqual(elasticScope.customerEsql(sql,datasets).datasets,datasets);calls.push({connection,sql,background,datasets});return response;}}});
  const summary=await app.fetchAppSecSummary(scope);assert.equal(summary.totalRepositories,2);assert.equal(summary.coveragePct,50);assert.equal(summary.findings,10);
  assert.deepEqual(calls[0].datasets,['gmi-appsec-scans']);assert.match(calls[0].sql,/MV_COUNT\(`gmi.appsec.repository`\) == 1/);
  assert.ok(calls[0].sql.indexOf('IN ("Acme/Alpha", "Acme/Other")')<calls[0].sql.indexOf('| STATS'));
  response=result('day,critical,high,resolved',[['2026-10-10',1,3,3]]);assert.equal((await app.fetchAppSecTrend(scope))[0].high,3);
  assert.match(calls[1].sql,/LATEST/);assert.match(calls[1].sql,/SUM\(`gmi.appsec.delta.resolved.total`\)/);
  const count=calls.length;await assert.rejects(()=>app.fetchAppSecSummary(),/Choose a customer/);assert.equal(calls.length,count);
  for(const responseRows of [[['Foreign/Repo',...summaryRow.slice(1)]],[summaryRow,summaryRow]]){
    response=result(summaryNames,responseRows);await assert.rejects(()=>app.fetchAppSecSummary(scope),/approved repositories/);
  }
  response=result(summaryNames,[summaryRow],{truncated:true});await assert.rejects(()=>app.fetchAppSecSummary(scope),/incomplete/);
}));

test('repository details reject unapproved targets before queries and never expose a mismatched finding response',async()=>withEnv({},async()=>{
  let calls=0,foreign=false;
  const scanNames='gmi.appsec.repository,@timestamp,gmi.appsec.scan.id,gmi.appsec.scan.status,gmi.appsec.findings.total,gmi.appsec.severity.critical,gmi.appsec.severity.high,gmi.appsec.delta.new.critical,gmi.appsec.delta.new.high,gmi.appsec.delta.resolved.total,gmi.appsec.gate.result';
  const findingNames='gmi.appsec.repository,gmi.appsec.scan.id,@timestamp,gmi.appsec.finding.fingerprint,gmi.appsec.finding.id,gmi.appsec.finding.severity,gmi.appsec.finding.kind,gmi.appsec.finding.title,gmi.appsec.finding.target,gmi.appsec.finding.status,package.name,vulnerability.id';
  const app=await load('lib/elastic-appsec.ts',{'./elastic-dashboard':{DashboardError},'./elastic-query-client':{executeEsql:()=>{throw Error('Legacy query');}},
    './customer-elastic-query':{executeCustomerEsql:async(_connection,sql)=>{calls++;
      if(sql.startsWith('FROM gmi-appsec-scans'))return result(scanNames,[['Acme/Alpha','2026-10-10','scan-a','completed',200,5,10,1,2,3,'fail']]);
      assert.match(sql,/LIMIT 101$/);return result(findingNames,Array.from({length:101},(_,i)=>[foreign?'Foreign/Repo':'Acme/Alpha','scan-a','2026-10-10','fp'+i,'f'+i,'High','vulnerability','Finding',null,'open','pkg','CVE-2026-1234']));
    }}});
  await assert.rejects(()=>app.fetchAppSecRepoDetail('Foreign/Repo',scope),e=>e.status===404);assert.equal(calls,0);
  let detail=await app.fetchAppSecRepoDetail('Acme/Alpha',scope);assert.equal(detail.findings.length,100);assert.equal(detail.findingsTruncated,true);
  foreign=true;detail=await app.fetchAppSecRepoDetail('Acme/Alpha',scope);assert.equal(detail.findings.length,0);assert.match(detail.findingsError,/could not be verified/);assert.doesNotMatch(JSON.stringify(detail),/Foreign/);
}));

test('runtime scope reads only metadata, rejects missing/customer/stale approvals and rechecks key or switch changes',async()=>withEnv({},async()=>{
  let reads=0,release=0,proof='proof',missing=false;
  const service=await load('lib/customer-appsec-routing-server.ts',{
    './persist':{applicationDatabase:()=>({connect:async()=>({release(){release++;}})})},'./elastic-dashboard':{DashboardError},
    './customer-connector-preview':{buildConnectorPreview:build},
    './customer-appsec-routing':{...policy,createAppSecRoutingStore:()=>({read:async(_provider,collect)=>{reads++;await collect();return missing?[]:[{companyId:'A',repositories:['Acme/Alpha'],bindingKey:proof}];}})},
    './db/connector-metadata.mjs':{readApplicationConnectorMetadata:async()=>metadata,readSavedApplicationCompanies:async()=>metadata.companies},
  });
  assert.equal((await service.appsecCustomerSetup()).companies.length,2);
  await assert.rejects(()=>service.loadCustomerAppSecScope(null),e=>e.status===400);assert.equal(reads,0);
  for(const id of ['UNKNOWN','DEMO','B'])await assert.rejects(()=>service.loadCustomerAppSecScope(id),e=>e.status===409);
  const ctx=await service.loadCustomerAppSecScope('A');await ctx.recheck();proof='changed';await assert.rejects(()=>ctx.recheck(),e=>e.status===409);
  const next=await service.loadCustomerAppSecScope('A');process.env.APPSEC_ELASTIC_API_KEY='rotated';await assert.rejects(()=>next.recheck(),e=>e.status===409);
  missing=true;await assert.rejects(()=>service.loadCustomerAppSecScope('A'),e=>e.status===409);
  process.env.VULN_REVIEWED_APPSEC_PROVIDERS='';assert.equal(await service.loadCustomerAppSecScope(null),null);await assert.rejects(()=>service.loadCustomerAppSecScope('A'),/not enabled/);
  assert.ok(release>0);
  for(const query of ['?companyId=','?companyId=A&companyId=B','?companyId=a%2Fb'])assert.throws(()=>service.appsecCompanyParameter(new Request('http://local/'+query)));
}));

for(const repository of [false,true])test(`${repository?'repository':'summary'} API withholds a successful source result if approval changes`,async()=>{
  let revoked=false,trendFailure=false;const calls=[];
  const service={appsecCompanyParameter:()=> 'A',appsecCustomerSetup:async()=>({reviewed:true,companies:[]}),loadCustomerAppSecScope:async()=>({scope,
    recheck:async()=>{calls.push('recheck');if(revoked)throw new DashboardError('Approval changed.',409);}})};
  const api=await load(repository?'app/api/appsec/repositories/[repo]/route.ts':'app/api/appsec/route.ts',{
    'next/server':{NextResponse:{json:(body,options={})=>({body,status:options.status??200,headers:options.headers})}},
    '@/lib/customer-appsec-routing-server':service,'@/lib/elastic-dashboard':{DashboardError},
    '@/lib/elastic-appsec':{appsecElasticConfig:()=>env,fetchAppSecSummary:async received=>{assert.equal(received,scope);return {rows:['private-fixture']};},
      fetchAppSecTrend:async()=>{if(trendFailure)throw Error('private-source');return [];},fetchAppSecRepoDetail:async(repo,received)=>{assert.equal(repo,'Acme/Alpha');assert.equal(received,scope);return {rows:['private-fixture']};}},
  });
  const get=()=>api.GET(new Request('http://local/api/appsec?companyId=A'),{params:Promise.resolve({repo:'Acme%2FAlpha'})});
  let response=await get();assert.equal(response.status,200);assert.equal(response.headers['Cache-Control'],'private, no-store');
  trendFailure=true;response=await get();assert.equal(response.status,200);if(!repository)assert.match(response.body.trendError,/unavailable/);
  revoked=true;response=await get();assert.equal(response.status,409);assert.doesNotMatch(JSON.stringify(response),/private-fixture|private-source/);assert.equal(calls.length,3);
  assert.equal(api.POST,undefined);
});
