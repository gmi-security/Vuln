import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {SourceTextModule,SyntheticModule,createContext} from 'node:vm';
import ts from 'typescript';

test('startup runs imports, data refresh and ticket tracking without automatic draft, sending or ticket mutation jobs',async()=>{
  const calls=[],timers=[];
  const context=createContext({process:{env:{NEXT_RUNTIME:'nodejs'}},console,setTimeout:fn=>{timers.push(fn);return {unref(){}};}});
  const names={ '@/lib/store':'ensureHydrated','@/lib/elastic-dashboard-store':'startElasticDashboardScheduler','@/lib/elastic-dashboard-jobs':'startDashboardJobWorker',
    '@/lib/reporting-queue':'startReportingQueueScheduler','@/lib/ticket-status-sync':'startTicketStatusSyncScheduler','@/lib/ticket-sla-escalation':'startTicketSlaEscalationScheduler',
    '@/lib/group-draft-dedup':'startGroupDraftDedupScheduler','@/lib/group-auto-create':'startGroupAutoCreateScheduler','@/lib/group-closure-validation':'startClosureValidationScheduler',
    '@/lib/risk-refresh-scheduler':'startRiskRefreshScheduler','@/lib/defender-worker':'startDefenderWorker'};
  const code=ts.transpileModule(await readFile('instrumentation.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const mod=new SourceTextModule(code,{context,importModuleDynamically:async name=>{
    const exports=name==='@/lib/group-severity-backfill'?['backfillWorstSeverity']:name==='@/lib/group-company-backfill'?['backfillAppCompanyId','backfillCustomerRouting']:
      name==='@/lib/group-priority-backfill'?['backfillTicketPriority']:[names[name]];
    assert.ok(exports.every(Boolean),'Unexpected startup dependency '+name);
    const loaded=new SyntheticModule(exports,function(){for(const key of exports)this.setExport(key,async()=>{calls.push(key);});},{context});
    await loaded.link(()=>{});await loaded.evaluate();return loaded;
  }});
  await mod.link(()=>{});await mod.evaluate();await mod.namespace.register();
  for(const run of timers)run();
  for(let i=0;i<10;i++)await new Promise(r=>setImmediate(r));
  assert.deepEqual(calls.sort(),['ensureHydrated','startDashboardJobWorker','startDefenderWorker','startElasticDashboardScheduler','startRiskRefreshScheduler','startTicketStatusSyncScheduler'].sort());
});


test('scheduled connector ticks repeat after success and failure without overlapping',async()=>{
  const source=ts.createSourceFile('store.ts',await readFile('lib/store.ts','utf8'),ts.ScriptTarget.Latest,true);
  for(const [name,tickName,guard] of [['startScheduler','schedulerTick','__vulnSchedulerTick'],['startScannerElasticExportScheduler','scannerElasticExportTick','__vulnScannerExportTick'],['startVulnersBridgeScheduler','vulnersBridgeTick','__vulnVulnersBridgeTick']]) {
    const declaration=source.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text===name);
    assert.ok(declaration,name);
    const state={},timers=[];let runs=0,finish,fail=false;
    const context=createContext({process:{env:{}},console:{error(){}},persistGlobal:state,
      setInterval:fn=>{timers.push(fn);return 1;},[tickName]:async()=>{runs++;await new Promise(resolve=>finish=resolve);if(fail)throw new Error('fixture failure');}});
    const code=ts.transpileModule(declaration.getText(source)+`; ${name}();`,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
    const mod=new SourceTextModule(code,{context});await mod.link(()=>{});await mod.evaluate();
    assert.equal(timers.length,1,name);timers[0]();timers[0]();assert.equal(runs,1,name+' blocks overlaps');
    finish();await state[guard];timers[0]();assert.equal(runs,2,name+' repeats');
    fail=true;finish();await state[guard];timers[0]();assert.equal(runs,3,name+' retries future tick after failure');finish();await state[guard];
  }
});
