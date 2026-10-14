import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

async function load(file, overrides, timers = []) {
  const context = vm.createContext({ console, process: { env: {} }, setInterval(fn, ms) { timers.push({ fn, ms }); return { unref() {} }; } });
  const code = ts.transpileModule(await readFile(file, 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
  const mod = new vm.SourceTextModule(code, { context });
  await mod.link(name => {
    assert.ok(overrides[name], `unexpected dependency ${name}`);
    const values = overrides[name];
    return new vm.SyntheticModule(Object.keys(values), function() { for (const [k,v] of Object.entries(values)) this.setExport(k,v); }, { context });
  });
  await mod.evaluate(); return mod.namespace;
}
const settled = () => new Promise(resolve => setImmediate(resolve));

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
  const saved = { revision: 1, daily: true, last_attempt_at: null, current_run: null };
  const db = { connect: async () => ({ query: dbQuery, release() {} }), query: dbQuery };
  async function dbQuery(sql) {
    if (sql.startsWith('SELECT revision,daily')) return { rows: [{ ...saved }] };
    if (sql.startsWith('UPDATE defender_connections SET last_attempt_at')) saved.last_attempt_at = new Date();
    return { rows: [] };
  }
  const mod = await load('lib/defender-store.ts', {
    'node:crypto': { randomUUID: () => 'test-run' }, './persist': { applicationDatabase: () => db },
    './defender-client': { DefenderError: Error, openDefender: () => ({}), sealDefender: () => 'test' },
  });
  const store = mod.createDefenderStore(db);
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), 'test-run');
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), null);
  saved.last_attempt_at = new Date(Date.now() - 86_400_001);
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), 'test-run');
  saved.daily = false; saved.last_attempt_at = null;
  assert.equal(await store.enqueue('CO-A', 'daily-scheduler'), null);
  assert.equal(await store.enqueue('CO-A', 'sync-all'), 'test-run');
});

test('daily claim returns the database decision and fails closed if it cannot be recorded', async () => {
  let rows = [], broken = false;
  const mod = await load('lib/background-job-runs.ts', { './patch-ticket-store': { patchTicketDatabase: async () => ({ query: async () => { if(broken) throw Error('db down'); return { rows }; } }) } });
  assert.equal(await mod.claimDailyJob('risk-refresh'), false);
  rows = [{ job: 'risk-refresh' }]; assert.equal(await mod.claimDailyJob('risk-refresh'), true);
  broken = true; await assert.rejects(mod.claimDailyJob('risk-refresh'), /db down/);
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
