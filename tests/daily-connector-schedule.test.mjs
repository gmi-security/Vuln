import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

let clock = Date.parse('2026-10-17T04:00:00Z');
class ClockDate extends Date {
  constructor(...args) { super(...(args.length ? args : [clock])); }
  static now() { return clock; }
}
async function load(file, overrides, timers = []) {
  const context = vm.createContext({ Date: ClockDate, console, process: { env: {} }, setInterval(fn, ms) { timers.push({ fn, ms }); return { unref() {} }; } });
  const code = ts.transpileModule(await readFile(file, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const mod = new vm.SourceTextModule(code, { context });
  await mod.link(async name => {
    if (name === './connector-sync-schedule') {
      const helper = new vm.SourceTextModule(ts.transpileModule(await readFile('lib/connector-sync-schedule.ts','utf8'), {compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText,{context});
      await helper.link(() => {}); return helper;
    }
    assert.ok(overrides[name], `unexpected dependency ${name}`);
    const values = overrides[name];
    return new vm.SyntheticModule(Object.keys(values), function() { for (const [k,v] of Object.entries(values)) this.setExport(k,v); }, { context });
  });
  await mod.evaluate(); return mod.namespace;
}
const settled = () => new Promise(resolve => setImmediate(resolve));

test('restart recovery resumes only the selected unfinished checkpoint once, even during daytime', async () => {
  const ast=ts.createSourceFile('store.ts',await readFile('lib/store.ts','utf8'),ts.ScriptTarget.Latest,true);
  const fn=ast.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='resumeInterruptedSpotlightSync');
  assert.ok(fn, 'the scheduler needs checkpoint recovery separate from the nightly start claim');
  for(const state of ['running','completed','failed','missing','busy','unmapped','storage-error','route-read-error']) {
    const calls=[], globals={}; let queryFails=state==='storage-error', busy=state==='busy', routeFails=state==='route-read-error';
    const context=vm.createContext({console,Date:ClockDate,syncJobGlobal:globals,
      csSpotlightSync:()=>({running:busy}),
      resolveSpotlightSelection:async()=>{if(state==='unmapped'||routeFails)throw Error('Route unavailable');return {companyId:'A',tenantKey:'A'};},
      getLatestSpotlightRunState:async tenant=>{assert.equal(tenant,'A');if(queryFails)throw Error('db unavailable');return state==='missing'?null:{id:'saved-run',status:['storage-error','route-read-error'].includes(state)?'running':state};},
      startCsSpotlightSync:async(...args)=>{calls.push(args);return {started:true};},
    });
    const mod=new vm.SourceTextModule(ts.transpileModule('export '+fn.getText(ast),{compilerOptions:{module:ts.ModuleKind.ESNext}}).outputText,{context});
    await mod.link(()=>{});await mod.evaluate();
    clock=Date.parse('2026-10-29T15:00:00Z');
    if(queryFails){await assert.rejects(()=>mod.namespace.resumeInterruptedSpotlightSync(),/db unavailable/);queryFails=false;}
    if(routeFails){await mod.namespace.resumeInterruptedSpotlightSync();routeFails=false;}
    await mod.namespace.resumeInterruptedSpotlightSync();
    await mod.namespace.resumeInterruptedSpotlightSync();
    assert.deepEqual(calls,['running','storage-error','route-read-error'].includes(state)?[['A','saved-run']]:[],state);
  }
});

test('Arizona nightly start is stable across daylight-saving changes, month boundaries and restarts', async () => {
  const {connectorSyncStart} = await load('lib/connector-sync-schedule.ts',{});
  for (const [at,want] of [
    ['2026-01-17T03:59:59.999Z',null],['2026-01-17T04:00:00Z','2026-01-17T04:00:00Z'],
    ['2026-07-17T04:00:00Z','2026-07-17T04:00:00Z'],['2026-11-02T04:00:00Z','2026-11-02T04:00:00Z'],
    ['2027-01-01T04:00:00Z','2027-01-01T04:00:00Z'],
    ['2026-10-17T06:59:59Z','2026-10-17T04:00:00Z'],['2026-10-17T07:00:00Z',null],
    ['2026-10-17T19:00:00Z',null],['2026-10-18T04:00:00Z','2026-10-18T04:00:00Z'],
  ]) assert.equal(connectorSyncStart(Date.parse(at)),want === null ? null : Date.parse(want),at);
  assert.equal(connectorSyncStart(NaN),null);
});

test('general connector scheduler starts at 9 PM, blocks duplicates after restart and waits again next day', async () => {
  const ast=ts.createSourceFile('store.ts',await readFile('lib/store.ts','utf8'),ts.ScriptTarget.Latest,true);
  const fn=ast.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='schedulerTick');
  const {connectorSyncStart}=await load('lib/connector-sync-schedule.ts',{});
  const s={settings:{schedule:{autoSyncEnabled:true,autoSyncIntervalHours:24,alertsEnabled:false,monthlyReportsEnabled:false}},meta:{lastMetricsSnapshotDay:'today',lastAutoSyncAt:null}};
  let starts=0,busy=false,claimed=null,recoveries=0;
  const context=vm.createContext({console,Date:ClockDate,store:()=>s,todayUtc:()=> 'today',markDirty(){},connectorSyncStart,
    resumeInterruptedSpotlightSync:async()=>{recoveries++;},
    claimDailyJob:async()=>{const slot=connectorSyncStart(clock);if(claimed===slot)return false;claimed=slot;return true;},
    syncAllStatus:()=>({running:busy}),startSyncAll:options=>{assert.equal(options.scheduled,true);starts++;return {started:true};}});
  const mod=new vm.SourceTextModule(ts.transpileModule('export '+fn.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText,{context});
  await mod.link(()=>{});await mod.evaluate();
  clock=Date.parse('2026-10-17T03:59:59Z');await mod.namespace.schedulerTick();assert.equal(starts,0);
  clock=Date.parse('2026-10-17T04:00:00Z');await mod.namespace.schedulerTick();assert.equal(starts,1);
  s.meta.lastAutoSyncAt=null;await mod.namespace.schedulerTick();assert.equal(starts,1,'durable claim survives loss of in-memory metadata');
  clock=Date.parse('2026-10-18T03:59:59Z');await mod.namespace.schedulerTick();assert.equal(starts,1);
  clock=Date.parse('2026-10-18T04:00:00Z');busy=true;await mod.namespace.schedulerTick();assert.equal(starts,1);
  busy=false;await mod.namespace.schedulerTick();assert.equal(starts,2);
  const previousRecoveries=recoveries;
  clock=Date.parse('2026-10-19T04:00:00Z');s.settings.schedule.autoSyncEnabled=false;await mod.namespace.schedulerTick();assert.equal(starts,2);
  assert.equal(recoveries,previousRecoveries,'disabled automatic imports must not resume');
});

test('ConnectWise automatic sync observes a durable daily claim across ticks and restarts; manual refresh remains available', async () => {
  let due = true, checks = 0, claims = 0;
  const overrides = {
    './patch-ticket-store': { savedConnection: async () => ({ target: 'cw', value: {} }), patchTicketDatabase: async () => ({ query: async () => { checks++; return { rows: [] }; } }) },
    './connectwise-client': { cwId: () => false, cwRequest: async () => assert.fail('no tickets to request') },
    './elastic-vuln-server': { elasticVulnEnabled: () => true },
    './background-job-runs': { claimDailyJob: async job => { assert.equal(job, 'ticket-status-sync'); claims++; const take = due; due = false; return take; }, recordJobRun: async () => {} },
  };
  const timers = [], first = await load('lib/ticket-status-sync.ts', overrides, timers);
  first.startTicketStatusSyncScheduler(); await settled();
  assert.equal(checks, 2);
  await timers[0].fn(); await settled(); assert.equal(checks, 2);
  const restarted = await load('lib/ticket-status-sync.ts', overrides);
  restarted.startTicketStatusSyncScheduler(); await settled(); assert.equal(checks, 2);
  assert.equal(claims, 3);
  await restarted.syncTicketStatuses(); assert.equal(checks, 4);
  due = true; await timers[0].fn(); await settled(); assert.equal(checks, 6);
});

test('risk scheduler skips a recent daily run but manual risk refresh bypasses cadence', async () => {
  let due = false, scored = 0, logFails = false;
  const timers = [];
  const overrides = {
    './elastic-vuln-server': { elasticVulnEnabled: () => true },
    './cve-enrichment-refresh': { refreshCveEnrichment: async () => ({ errors: 0 }) },
    './defender-platform': { reconcileDefenderPlatform: async () => {} },
    './defender-risk': { refreshDefenderRisk: async () => { scored++; return { findingsScored: 0, errors: 0 }; } },
    './finding-risk-compute': { computeFindingRiskForTenant: async () => ({ findingsScored: 0, errors: 0 }) },
    './risk-scoring-store': { riskScoringDatabase: async () => ({ query: async sql => ({ rows: sql.includes('pg_try_advisory_lock') ? [{ locked: true }] : [] }) }), recordRiskSnapshot: async () => {} },
    './background-job-runs': { claimDailyJob: async job => { assert.equal(job, 'risk-refresh'); const take = due; due = false; return take; }, recordJobRun: async () => { if (logFails) throw Error('diagnostic log unavailable'); } },
  };
  const mod = await load('lib/risk-refresh-scheduler.ts', overrides, timers);
  mod.startRiskRefreshScheduler(); await settled(); assert.equal(scored, 0);
  logFails = true;
  mod.triggerRiskRefreshNow(); await settled(); assert.equal(scored, 1);
  logFails = false;
  due = true; await timers[0].fn(); await settled(); assert.equal(scored, 2);
  await timers[0].fn(); await settled(); assert.equal(scored, 2);
});

test('Defender daily gate allows first imports and failed-first retries, prevents early repeats and honors disabled customers', async () => {
  clock = Date.parse('2026-10-17T04:00:00Z');
  const saved = { revision: 1, daily: true, last_attempt_at: null, current_run: null };
  const db = { connect: async () => ({ query: dbQuery, release() {} }), query: dbQuery };
  async function dbQuery(sql) {
    if (sql.startsWith('SELECT revision,daily')) return { rows: [{ ...saved }] };
    if (sql.startsWith('UPDATE defender_connections SET last_attempt_at')) saved.last_attempt_at = new ClockDate();
    return { rows: [] };
  }
  const mod = await load('lib/defender-store.ts', {
    'node:crypto': { randomUUID: () => 'test-run' }, './persist': { applicationDatabase: () => db },
    './defender-client': { DefenderError: Error, openDefender: () => ({}), sealDefender: () => 'test' },
  });
  const store = mod.createDefenderStore(db);
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), 'test-run');
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), null);
  clock = Date.parse('2026-10-18T04:00:00Z');
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), 'test-run');
  saved.daily = false; saved.last_attempt_at = null;
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), null);
  assert.equal(await store.enqueue('CO-A', 'sync-all'), 'test-run');
});

test('daily claim returns the database decision and fails closed if it cannot be recorded', async () => {
  clock = Date.parse('2026-10-17T04:00:00Z');
  let rows = [], broken = false;
  const mod = await load('lib/background-job-runs.ts', { './patch-ticket-store': { patchTicketDatabase: async () => ({ query: async () => { if(broken) throw Error('db down'); return { rows }; } }) } });
  assert.equal(await mod.claimDailyJob('risk-refresh'), false);
  rows = [{ job: 'risk-refresh' }]; assert.equal(await mod.claimDailyJob('risk-refresh'), true);
  broken = true; await assert.rejects(mod.claimDailyJob('risk-refresh'), /db down/);
});

test('nightly provider claims do not start daytime catch-up imports after an app restart', async () => {
  clock = Date.parse('2026-10-17T03:59:59Z');
  let calls = 0;
  const mod = await load('lib/background-job-runs.ts', {'./patch-ticket-store':{patchTicketDatabase:async()=>({query:async()=>{calls++;return {rows:[{job:'risk-refresh'}]};}})}});
  assert.equal(await mod.claimDailyJob('risk-refresh'), false);
  assert.equal(calls, 0);
  clock = Date.parse('2026-10-17T04:00:00Z');
  assert.equal(await mod.claimDailyJob('risk-refresh'), true);
  assert.equal(calls, 1);
});

test('Defender waits until 9 PM Arizona even for first import; manual sync bypasses time', async () => {
  clock = Date.parse('2026-10-17T03:59:59Z');
  let inserts = 0;
  const query = async sql => {
    if(sql.startsWith('SELECT revision,daily')) return {rows:[{revision:1,daily:true,last_attempt_at:null}]};
    if(sql.startsWith('INSERT INTO defender_import_runs')) inserts++;
    return {rows:[]};
  };
  const db={query,connect:async()=>({query,release(){}})};
  const mod=await load('lib/defender-store.ts',{'node:crypto':{randomUUID:()=> 'run'},'./persist':{applicationDatabase:()=>db},'./defender-client':{DefenderError:Error,openDefender:()=>({}),sealDefender:()=>''}});
  const store=mod.createDefenderStore(db);
  assert.equal(await store.enqueue('CO-A','daily-scheduler'),null);
  assert.equal(inserts,0);
  assert.equal(await store.enqueue('CO-A','manual'), 'run');
  assert.equal(inserts,1);
  clock = Date.parse('2026-10-17T04:00:00Z');
  assert.equal(await store.enqueue('CO-A','daily-scheduler'),'run');
});

test('scheduled Defender sync-all uses the existing daily gate; manual sync can still enqueue', async () => {
  const source = await readFile('lib/store.ts', 'utf8');
  const ast = ts.createSourceFile('store.ts', source, ts.ScriptTarget.Latest, true);
  const fn = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'importFromDefender');
  assert.ok(fn);
  const actors = [];
  const context = vm.createContext({ process: { env: { DATABASE_URL: 'test-only' } }, defenderStore: () => ({
    list: async () => [{ companyId: 'CO-A' }], enqueue: async (id, actor) => { assert.equal(id, 'CO-A'); actors.push(actor); return actor === 'daily-scheduler' ? null : 'queued-id'; },
  }) });
  const code = ts.transpileModule(fn.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const mod = new vm.SourceTextModule(code, { context, importModuleDynamically: async name => {
    const exports = name === './defender-config' ? { syncDefenderEnvironment: async () => {} } : { triggerDefenderWorker: async () => {} };
    assert.ok(['./defender-config', './defender-worker'].includes(name));
    const dep = new vm.SyntheticModule(Object.keys(exports), function() { for (const [k,v] of Object.entries(exports)) this.setExport(k,v); }, { context });
    await dep.link(() => {}); await dep.evaluate(); return dep;
  } });
  await mod.link(() => {}); await mod.evaluate();
  assert.equal((await mod.namespace.importFromDefender({ scheduled: true })).queued, 0);
  assert.equal((await mod.namespace.importFromDefender()).queued, 1);
  assert.deepEqual(actors, ['daily-scheduler', 'sync-all']);
});
