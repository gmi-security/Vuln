import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

async function fixture() {
  let clock=Date.parse('2026-11-18T20:00:00Z');
  const delays=[];
  class ClockDate extends Date { static now(){return clock;} }
  const context=vm.createContext({console,Error,Date:ClockDate,setTimeout(fn,ms){delays.push(ms);clock+=ms;fn();}});
  const modules=new Map();
  async function load(file) {
    if(modules.has(file))return modules.get(file);
    const code=ts.transpileModule(await readFile(file,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
    const m=new vm.SourceTextModule(code,{context});modules.set(file,m);
    await m.link(async name=> name==='./patch-ticket-store' ? new vm.SyntheticModule(['patchTicketDatabase'],function(){this.setExport('patchTicketDatabase',()=>assert.fail('unit runner must not contact DB'));},{context}) : load(`lib/${name.slice(2)}.ts`));
    await m.evaluate();return m;
  }
  return {api:(await load('lib/connector-sync-batch.ts')).namespace,delays,now:()=>clock};
}
function batch(progress) {
  const saves=[];
  return {startedAt:'2026-11-18T04:00:14.677Z',progress,save:async(p,done=false)=>saves.push({p:structuredClone(p),done}),release:async()=>{},saves};
}

test('recovery skips finished work, resumes the unstarted queue and preserves staggering',async()=>{
  const f=await fixture(), calls=[];
  const saved=batch({version:1,nextStartAt:f.now()+10_000,entries:[{connector:'Nessus',startedAt:1,result:{connector:'Nessus',configured:true,ok:true}}]});
  const jobs=['Nessus','CrowdStrike Devices','CrowdStrike Spotlight'].map(connector=>({connector,ready:true,run:async()=>{calls.push(connector);return {message:'started'};}}));
  const out=await f.api.runConnectorSyncJobs(jobs,saved);
  assert.deepEqual(calls,['CrowdStrike Devices','CrowdStrike Spotlight']);
  assert.deepEqual(f.delays,[10_000,1_500_000]);
  assert.equal(out.every(r=>r.ok),true);
  assert.equal(saved.saves.at(-1).done,true);
});

test('unknown scanner side effects are not replayed; checkpoint-aware Spotlight is recovered',async()=>{
  const f=await fixture(),calls=[];
  const saved=batch({version:1,nextStartAt:0,entries:[{connector:'Scanner',startedAt:10},{connector:'Spotlight',startedAt:20}]});
  const out=await f.api.runConnectorSyncJobs([
    {connector:'Scanner',ready:true,run:async()=>assert.fail('must not duplicate remote action')},
    {connector:'Spotlight',ready:true,run:async()=>assert.fail('must use checkpoint recovery'),recover:async at=>{calls.push(at);return {message:'resumed'};}},
  ],saved);
  assert.equal(out[0].ok,false);assert.match(out[0].error,/interrupted/i);
  assert.equal(out[1].ok,true);assert.deepEqual(calls,[20]);
});

test('legacy claim recovers only Spotlight and reports unknown previous scanner actions',async()=>{
  const f=await fixture(),calls=[];
  const saved=batch(null);
  const out=await f.api.runConnectorSyncJobs([
    {connector:'Nessus',ready:true,run:async()=>assert.fail('unknown legacy action')},
    {connector:'Spotlight',ready:true,run:async()=>assert.fail('must reconcile'),recover:async at=>{calls.push(at);return {}; }},
    {connector:'Disabled',ready:false,run:async()=>assert.fail('disabled')},
  ],saved);
  assert.equal(out[0].ok,false);assert.match(out[0].error,/legacy/);
  assert.deepEqual(calls,[Date.parse(saved.startedAt)]);assert.equal(out[1].ok,true);
  assert.equal(out[2].configured,false);assert.equal(saved.saves.at(-1).done,true);
});

test('journal write failure prevents provider launch; a post-call failure leaves recoverable intent',async()=>{
  const f=await fixture();let calls=0,writes=0;
  const saved=batch({version:1,nextStartAt:0,entries:[]});
  saved.save=async()=>{throw Error('database lost');};
  const jobs=[{connector:'Spotlight',ready:true,run:async()=>{calls++;return {};}}];
  await assert.rejects(f.api.runConnectorSyncJobs(jobs,saved),/database lost/);assert.equal(calls,0);
  let durable;
  saved.progress={version:1,nextStartAt:0,entries:[]};
  saved.save=async p=>{if(++writes===2)throw Error('database lost');durable=structuredClone(p);};
  await assert.rejects(f.api.runConnectorSyncJobs(jobs,saved),/database lost/);
  assert.equal(calls,1);assert.equal(durable.entries[0].result,undefined);
});

test('manual runner preserves warning/error aggregation and skips disabled connectors',async()=>{
  const f=await fixture();
  const out=await f.api.runConnectorSyncJobs([
    {connector:'Disabled',ready:false,run:async()=>assert.fail('disabled')},
    {connector:'Partial',ready:true,run:async()=>({tenants:[{error:'provider failed'}]})},
    {connector:'Error',ready:true,run:async()=>{throw Error('timeout');}},
    {connector:'Good',ready:true,run:async()=>({count:2})},
  ]);
  assert.deepEqual(Array.from(out,r=>r.ok),[false,false,false,true]);
  assert.match(out[1].error,/1 tenant import failed/);assert.equal(out[2].error,'timeout');
  assert.equal(out[3].result.count,2);assert.deepEqual(f.delays,[1_500_000,1_500_000]);
});

test('recovery rejects a changed Spotlight customer scope before contacting the provider',async()=>{
  const f=await fixture();let calls=0;
  const saved=batch({version:1,nextStartAt:0,entries:[{connector:'Spotlight',startedAt:1,scope:'customer-A:approval-1'}]});
  const out=await f.api.runConnectorSyncJobs([{connector:'Spotlight',ready:true,getScope:async()=> 'customer-B:approval-1',
    run:async()=>{calls++;return {};},recover:async()=>{calls++;return {};}}],saved);
  assert.equal(calls,0);assert.equal(out[0].ok,false);assert.match(out[0].error,/scope changed/i);
});

async function storeFunction(name,globals) {
  const source=await readFile('lib/store.ts','utf8'),ast=ts.createSourceFile('store.ts',source,ts.ScriptTarget.Latest,true);
  const fn=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text===name);
  const code=ts.transpileModule((fn.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword)?'':'export ')+fn.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  const m=new vm.SourceTextModule(code,{context:vm.createContext({console,Date,...globals})});await m.link(()=>{});await m.evaluate();return m.namespace[name];
}

test('Spotlight recovery honors the selected customer and does not retry a completed nightly failure',async()=>{
  const since=Date.parse('2026-11-18T04:50:00Z');
  for(const status of ['running','completed','failed','older-failed','missing','unmapped']) {
    const calls=[];
    const recover=await storeFunction('recoverScheduledSpotlightStart',{
      csSpotlightSync:()=>({running:status==='busy'}),
      resolveSpotlightSelection:async()=>{if(status==='unmapped')throw Error('route unavailable');return {tenantKey:'A',companyId:'A'};},
      getLatestSpotlightRunState:async tenant=>{assert.equal(tenant,'A');return status==='missing'?null:{id:'run-A',status:status==='older-failed'?'failed':status,finishedAt:new Date(since+(status==='older-failed'?-1000:1000)).toISOString()};},
      startCsSpotlightSync:async(...args)=>{calls.push(args);return {started:true};},
    });
    if(status==='unmapped'){await assert.rejects(recover(since),/route unavailable/);continue;}
    const result=await recover(since);
    if(status==='failed')assert.match(result.error,/already failed/);
    assert.deepEqual(calls,['running','older-failed','missing'].includes(status)?[['A',status==='running'?'run-A':undefined,true,undefined]]:[],status);
  }
});

test('an unrelated or pre-checkpoint busy Spotlight job cannot acknowledge a scheduled start',async()=>{
  const recover=await storeFunction('recoverScheduledSpotlightStart',{
    ConnectorSyncDeferredError:Error,csSpotlightSync:()=>({running:true,tenant:'customer-B'}),
    resolveSpotlightSelection:async()=>({tenantKey:'A',companyId:'A'}),
    getLatestSpotlightRunState:async()=>null,
    startCsSpotlightSync:async()=>assert.fail('do not overlap'),
  });
  await assert.rejects(recover(Date.now()),/in progress/i);
});

test('a busy-provider deferral leaves the persisted intent unfinished for the next recovery',async()=>{
  const f=await fixture();
  const saved=batch({version:1,nextStartAt:0,entries:[{connector:'Spotlight',startedAt:1,scope:'A'}]});
  await assert.rejects(f.api.runConnectorSyncJobs([{connector:'Spotlight',ready:true,getScope:async()=> 'A',
    run:async()=>assert.fail('must recover'),recover:async()=>{throw new f.api.ConnectorSyncDeferredError('busy');}}],saved),/busy/);
  assert.equal(saved.saves.at(-1).done,false);assert.equal(saved.saves.at(-1).p.entries[0].result,undefined);
});

test('scheduled Spotlight start acknowledges only a durable checkpoint; manual start remains immediate',async()=>{
  let checkpoint,finish;const globals={};
  const start=await storeFunction('startCsSpotlightSync',{
    syncJobGlobal:globals,resolveSpotlightSelection:async()=>({config:{label:'A'}}),
    csSpotlightSync:()=>globals.__vulnCsSpotlightSync??{running:false},
    importFromCrowdstrikeSpotlight:async(_selection,_resume,onCheckpoint)=>{checkpoint=onCheckpoint;return new Promise(resolve=>{finish=resolve;});},
  });
  let accepted=false;const waiting=start(undefined,undefined,true).then(result=>{accepted=true;return result;});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(accepted,false);
  checkpoint();assert.equal((await waiting).started,true);
  finish({findingsImported:1});await new Promise(resolve=>setImmediate(resolve));
  assert.equal((await start()).started,true);finish({error:'test stop'});
});

test('Spotlight failure before checkpoint returns a failed launch instead of hanging the queue',async()=>{
  const globals={};
  const start=await storeFunction('startCsSpotlightSync',{
    syncJobGlobal:globals,resolveSpotlightSelection:async()=>({config:{label:'A'}}),
    csSpotlightSync:()=>globals.__vulnCsSpotlightSync??{running:false},
    importFromCrowdstrikeSpotlight:async()=>({error:'token service failed'}),
  });
  const result=await start(undefined,undefined,true);
  assert.equal(result.started,false);assert.equal(result.error,'token service failed');
});

test('Spotlight scope changes with the connection or approval, but never contains its secret',async()=>{
  const scope=await storeFunction('spotlightSelectionScope',{});
  const selected={tenantKey:'A',companyId:'A',config:{sourceRef:'secondary',clientId:'client-a',baseUrl:'https://api.crowdstrike.com',clientSecret:'do-not-store'}};
  const original=scope(selected);
  assert.notEqual(scope({...selected,config:{...selected.config,clientId:'client-b'}}),original);
  assert.notEqual(scope({...selected,reviewedScope:{bindingKey:'approval-b'}}),original);
  assert.equal(scope({...selected,config:{...selected.config,clientSecret:'rotated'}}),original);
  assert.equal(original.includes('do-not-store'),false);
});

test('deferred scheduled work releases ownership without completion hooks or a false failure',async()=>{
  const globals={};let releases=0,hooks=0,flushes=0;
  class Deferred extends Error {}
  const start=await storeFunction('startSyncAll',{
    ConnectorSyncDeferredError:Deferred,syncJobGlobal:globals,
    syncAllStatus:()=>globals.__vulnSyncAll??{running:false},
    syncAllConnectors:async()=>{throw new Deferred('waiting');},
    runPostSyncTasks:async()=>{hooks++;},flushNow:async()=>{flushes++;},
  });
  assert.equal(start({scheduled:true,batch:{release:async()=>{releases++;}}}).started,true);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(releases,1);assert.equal(hooks,0);assert.equal(flushes,0);
  assert.equal(globals.__vulnSyncAll.error,null);assert.equal(globals.__vulnSyncAll.finishedAt,null);
});
