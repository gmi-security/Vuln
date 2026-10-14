import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule } from 'node:vm';
import ts from 'typescript';

async function load(file, stubs = {}) {
  const source = await readFile(file, 'utf8').catch(e => e.code === 'ENOENT' ? 'export {}' : Promise.reject(e));
  const dependency = name => {
    assert.ok(stubs[name], `Unexpected import ${name}`);
    const values = stubs[name];
    return new SyntheticModule(Object.keys(values), function(){for(const key of Object.keys(values)) this.setExport(key,values[key]);});
  };
  const mod = new SourceTextModule(ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,
    {importModuleDynamically:async name=>{const value=dependency(name);await value.link(()=>{});await value.evaluate();return value;}});
  await mod.link(dependency); await mod.evaluate(); return mod.namespace;
}
const model = await load('lib/customer-connector-sync-model.ts');
const base = { companyId:'A', providers:[], queries:[], now:Date.parse('2026-10-14T12:00:00Z') };
test('saved-query sync rejects foreign, deleted and unassigned tiles before refreshing', async () => {
  const selected = await load('lib/reporting-direct-sources.ts');
  const rows = [
    {id:'a',title:'A',source:'elastic',companyId:'A'},
    {id:'b',title:'B',source:'elastic',companyId:'B'},
    {id:'none',title:'None',source:'elastic'},
  ];
  assert.deepEqual(rows.filter(q=>selected.reportingTileCompanyId(q,'','')==='A').map(q=>q.id),['a']);
  assert.equal(typeof model.requireSyncAction,'function');
  const status={companyId:'A',rows:model.customerSyncRows({...base,queries:[rows[0]]})};
  for(const id of ['query:b','query:none','query:deleted','shared:nessus']) assert.throws(()=>model.requireSyncAction(status,id));
  assert.equal(model.requireSyncAction(status,'query:a').id,'query:a');
  status.rows[0].canSync=false;
  assert.throws(()=>model.requireSyncAction(status,'query:a'));
});
test('failed Defender attempt retains last success and never exposes credentials or raw errors', () => {
  const rows = model.customerSyncRows({...base, providers:['defender'], defender:{last_success_at:'2026-10-13T12:00:00Z',status:'failed',fetched:32,error:'SECRET response',secret:'SECRET'}});
  assert.equal(rows[0].lastSuccessAt,'2026-10-13T12:00:00.000Z');
  assert.equal(rows[0].state,'failed'); assert.equal(rows[0].canSync,true);
  assert.ok(!JSON.stringify(rows).includes('SECRET'));
});
test('running Defender jobs block duplicate imports while queued or expired jobs can be resumed', () => {
  for(const [status,lease,state] of [['running','2026-10-14T12:05:00Z','running'],['running','2026-10-14T11:00:00Z','interrupted'],['queued',null,'queued']]){
    const [row] = model.customerSyncRows({...base,providers:['defender'],defender:{status,lease_until:lease}});
    assert.equal(row.state,state); assert.equal(row.canSync,state!=='running');
  }
});
test('historical Spotlight evidence cannot enable an unconfigured import or reveal another live job', () => {
  const [row] = model.customerSyncRows({...base,providers:['crowdstrike'],spotlight:{status:'completed',last_success_at:'2026-10-12T12:00:00Z'},spotlightAvailable:false});
  assert.equal(row.lastSuccessAt,'2026-10-12T12:00:00.000Z'); assert.equal(row.canSync,false);
  assert.equal(row.action,'sync');
});
test('query refreshes keep distinct success times, errors, lease and throttle states', () => {
  const rows=model.customerSyncRows({...base,queries:[
    {id:'one',title:'Coverage',source:'elastic',refreshed_at:'2026-10-12T10:00:00Z',last_error:'private provider error'},
    {id:'two',title:'Severity',source:'crowdstrike',refreshed_at:'2026-10-13T10:00:00Z',refresh_lease_until:'2026-10-14T12:05:00Z'},
    {id:'three',title:'Trend',source:'elastic',attempted_at:'2026-10-14T11:59:50Z'},
  ]});
  assert.equal(rows[0].id,'query:one'); assert.equal(rows[0].state,'failed'); assert.equal(rows[0].canSync,true);
  assert.equal(rows[1].lastSuccessAt,'2026-10-13T10:00:00.000Z'); assert.equal(rows[1].canSync,false);
  assert.equal(rows[2].canSync,false); assert.equal(rows[2].lastSuccessAt,null);
  assert.ok(!JSON.stringify(rows).includes('private provider error'));
});
test('shared and unsupported sources have no customer sync action and unknown is not never synced', () => {
  const rows=model.customerSyncRows({...base,providers:['nessus','nessus','misp','qualys']});
  assert.equal(rows.length,3);
  for(const row of rows){assert.equal(row.canSync,false);assert.equal(row.lastSuccessAt,null);assert.equal(row.state,'unavailable');}
});

test('sync API enforces session, origin, rollout and a selected customer before dispatch', async () => {
  const calls=[]; let denied=false,enabled=true;
  class DashboardError extends Error{constructor(message,status=400){super(message);this.status=status;}}
  const api=await load('app/api/elastic-dashboard/customer-sync/route.ts',{
    '@/lib/elastic-dashboard-http':{dashboardAccess:async(req,mutation)=>{calls.push(['access',mutation]);if(denied)throw new DashboardError('denied',403);return {actor:'member'};},dashboardBody:req=>req.json(),dashboardJson:(body,status=200)=>({body,status}),dashboardFailure:e=>({status:e.status||503})},
    '@/lib/elastic-dashboard':{DashboardError},'@/lib/remediation-server':{remediationUiEnabled:()=>enabled},
    '@/lib/customer-connector-sync-service':{readCustomerSyncStatus:async c=>{calls.push(['read',c]);return {companyId:c};},startCustomerSync:async(c,id,actor)=>{calls.push(['start',c,id,actor]);return {queued:true};}},
  });
  assert.equal(typeof api.GET,'function');
  const req=(company='A',body={id:'defender'})=>new Request('http://localhost/api/elastic-dashboard/customer-sync?companyId='+company,{method:'POST',body:JSON.stringify(body)});
  assert.equal((await api.POST(req())).status,202); assert.deepEqual(calls.at(-1),['start','A','defender','member']);
  const before=calls.filter(c=>c[0]==='start').length;
  assert.equal((await api.POST(req(''))).status,400);
  assert.equal((await api.POST(req('A',{id:'defender',companyId:'B'}))).status,400);
  denied=true; assert.equal((await api.POST(req())).status,403); denied=false;enabled=false;
  assert.equal((await api.GET(new Request('http://localhost/api/elastic-dashboard/customer-sync?companyId=A'))).status,404);
  assert.equal(calls.filter(c=>c[0]==='start').length,before);
});

test('manual Defender worker claims only the requested customer and does not schedule other imports', async () => {
  const claims=[],publications=[];let schedules=0,configSyncs=0;
  const worker=await load('lib/defender-worker.ts',{
    './defender-client':{createDefenderClient:()=>{},DefenderError:Error,normalizeDefenderRecord:r=>r},
    './defender-store':{defenderStore:()=>({schedule:async()=>{schedules++;},claim:async id=>{claims.push(id);return null;}})},
    './defender-config':{syncDefenderEnvironment:async()=>{configSyncs++;}},
    './defender-platform':{reconcileDefenderPlatform:async(...args)=>{publications.push(args);}},
  });
  await worker.triggerDefenderWorker('A');
  assert.deepEqual(claims,['A']);assert.equal(schedules,0);assert.equal(configSyncs,0);
  assert.deepEqual(publications,[[true,'A']]);
});

test('sync service scopes database metadata and dispatch; GET never imports or refreshes', async () => {
  const actions=[],reads=[];
  const direct=await load('lib/reporting-direct-sources.ts'),spotlight=await load('lib/spotlight-import.ts');
  const queries=[{id:'a',title:'Alpha tile',source:'elastic',hasOwner:true,companyId:'A'}, {id:'b',title:'PRIVATE_B',source:'elastic',hasOwner:true,companyId:'B'}, {id:'unassigned',title:'PRIVATE_NONE',source:'elastic',hasOwner:true,companyId:null}];
  const client={release(){},async query(sql,params=[]){
    reads.push({sql,params});
    if(sql.includes('to_regclass'))return {rows:[{name:params[0]}]};
    if(sql.includes('c.last_success_at'))return {rows:params[0]==='A'?[{status:'succeeded',last_success_at:'2026-10-13T00:00:00Z'}]:[]};
    if(sql.includes('FROM spotlight_import_runs r'))return {rows:[]};
    if(sql.includes('FROM elastic_dashboard_queries'))return {rows:queries};
    if(/^(BEGIN|COMMIT|ROLLBACK|SET LOCAL)/.test(sql))return {rows:[]};
    throw new Error('Unexpected SQL '+sql);
  }};
  const pool={connect:async()=>client};
  const service=await load('lib/customer-connector-sync-service.ts',{
    './persist':{applicationDatabase:()=>pool},'./elastic-dashboard':{DashboardError:class extends Error{}},
    './customer-connector-status-service':{customerDashboardPool:()=>pool,readCustomerConnectorStatus:async id=>{assert.equal(id,'A');return {items:[{provider:'defender'},{provider:'crowdstrike'},{provider:'elastic'},{provider:'nessus'}]};}},
    './db/connector-metadata.mjs':{readSavedApplicationCompanies:async()=>[{id:'A',name:'Alpha'},{id:'B',name:'Beta'}]},
    './customer-connector-sync-model':model,'./reporting-direct-sources':direct,'./spotlight-import':spotlight,
    './crowdstrike':{falconConfigs:()=>[{customerName:'Alpha',label:'Alpha source'}]},
    './customer-spotlight-routing-server':{loadReviewedSpotlightRoutes:async()=>null},
    './store':{getCsSpotlightSyncStatus:()=>({running:false}),ensureHydrated:async()=>{},startCsSpotlightSync:async c=>{actions.push(['spotlight',c]);return {started:true};}},
    './defender-store':{defenderStore:()=>({enqueue:async(c,actor)=>{actions.push(['defender',c,actor]);return 'run';}})},
    './defender-worker':{triggerDefenderWorker:async c=>{actions.push(['worker',c]);}},
    './elastic-dashboard-store':{requestCustomerQueryRefresh:async(c,id,actor)=>{actions.push(['query',c,id,actor]);}},
  });
  const result=await service.readCustomerSyncStatus('A');
  assert.equal(actions.length,0);assert.ok(!JSON.stringify(result).includes('PRIVATE_'));
  assert.deepEqual(result.rows.filter(r=>r.id.startsWith('query:')).map(r=>r.id),['query:a']);
  for(const read of reads.filter(r=>r.sql.includes('c.last_success_at')||r.sql.includes('FROM spotlight_import_runs r')))assert.deepEqual(read.params,['A']);
  assert.ok(reads.some(r=>r.sql==='BEGIN READ ONLY'));
  for(const id of ['query:b','query:unassigned','shared:nessus'])await assert.rejects(()=>service.startCustomerSync('A',id,'member'));
  assert.equal(actions.length,0);
  await service.startCustomerSync('A','defender','member');
  await service.startCustomerSync('A','crowdstrike-spotlight','member');
  await service.startCustomerSync('A','query:a','member');
  assert.deepEqual(actions,[['defender','A','member'],['worker','A'],['spotlight','A'],['query','A','a','member']]);
  const old=process.env.REPORTING_CUSTOMER_TILE_IDS;
  try {
    process.env.REPORTING_CUSTOMER_TILE_IDS='{"A":["legacy","unassigned"]}';
    queries.push({id:'legacy',title:'Legacy tile',source:'elastic',hasOwner:false,companyId:null});
    assert.deepEqual((await service.readOwnedQuerySync(client,'A')).map(q=>q.id),['a','legacy']);
  } finally {if(old===undefined)delete process.env.REPORTING_CUSTOMER_TILE_IDS;else process.env.REPORTING_CUSTOMER_TILE_IDS=old;}
});

test('customer publication only loads that customer and respects the paused patch scheduler', async () => {
  const published=[],scores=[],listed=[];const previous=process.env.VULN_DISABLE_SCHEDULER;
  process.env.VULN_DISABLE_SCHEDULER='true';
  try {
    const platform=await load('lib/defender-platform.ts',{
      './defender-store':{defenderStore:()=>({list:async id=>{listed.push(id);return [{companyId:'A',currentRun:'a'},{companyId:'B',currentRun:'b'}].filter(c=>!id||id===c.companyId);},platformSnapshot:async id=>({companyId:id,runId:id,findings:[],devices:[]})})},
      './store':{ensureHydrated:async()=>{},defenderProjectedRun:()=>null,publishDefenderSnapshot:s=>published.push(s.companyId),invalidateDefenderPublication(){},flushNow:async()=>{}},
      './defender-risk':{refreshDefenderRisk:async(...args)=>{scores.push(args);}},
      './reporting-queue':{refreshReportingQueue:async()=>{assert.fail('Paused draft generator must not run');}},
    });
    await platform.reconcileDefenderPlatform(true,'A');
    assert.deepEqual(listed,['A']);assert.deepEqual(published,['A']);assert.deepEqual(scores,[[false,'A']]);
  } finally {if(previous===undefined)delete process.env.VULN_DISABLE_SCHEDULER;else process.env.VULN_DISABLE_SCHEDULER=previous;}
});
