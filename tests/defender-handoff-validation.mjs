import assert from 'node:assert/strict';
import {refreshModules} from './defender-refresh-fixture.mjs';
import {legacyPersistenceFixture} from './legacy-persistence-fixture.mjs';
import {createRehearsalGate,captureLegacyCustomer,rehearseDefenderHandoff} from './defender-handoff-rehearsal.mjs';
import {privateShadowDatabase,reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
import {readDefenderPublication,publishDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
export async function verifyLegacyHandoff({source,target,pool,baseline,company,run,pass}){
  await privateShadowDatabase(source,'source');await privateShadowDatabase(target,'target');
  const persistence=await legacyPersistenceFixture(pool),modules=await refreshModules({persist:persistence.persist});
  const memory=structuredClone(baseline);memory.meta.defenderGenerations[company.id]=run;
  globalThis.__vulnStore=memory;
  const finding=[...memory.findings.values()][0],gate=createRehearsalGate();
  const captureMemory=()=>captureLegacyCustomer(memory,company.id);
  const args={source,target,companyId:company.id,gate,captureMemory,flush:options=>modules.store.flushNow(options),
    prepare:modules.candidate.prepareDefenderRefreshCandidate,capture:modules.assessment.captureDefenderRefreshAssessment};
  const count=async()=>(await target.query('SELECT count(*)::int n FROM defender_shadow_generations')).rows[0].n;
  const disk=async()=>JSON.parse(JSON.stringify(await (await persistence.fresh()).loadSnapshot()));
  const patch=values=>gate.run(()=>modules.store.updateFinding(finding.id,values));
  const pointer=await readDefenderPublication(target,company.id);
  try{
    await modules.store.flushNow({throwOnError:true});
    await patch({status:'Resolved',assignee:'pending-analyst'});
    const resolvedAt=finding.resolvedAt;
    assert.notEqual((await disk()).findings[0][1].assignee,'pending-analyst','actual legacy update returns before durable save');
    const before=await count();
    const missing=await rehearseDefenderHandoff({...args,flush:async()=>{}});
    assert.equal(missing.state,'refused');assert.match(missing.reason,/differs from memory/);assert.equal(await count(),before);
    const success=await rehearseDefenderHandoff(args);assert.equal(success.state,'rehearsed');assert.equal(success.handoffAllowed,false);assert.equal(success.publicationAllowed,false);
    const copied=(await target.query(reconstructShadowSql,[company.id,success.projectionId])).rows[0].record;
    assert.equal(copied.status,'Resolved');assert.equal(copied.resolvedAt,resolvedAt);assert.equal(copied.assignee,'pending-analyst');
    const restarted=await disk();assert.equal(restarted.findings[0][1].assignee,'pending-analyst');assert.equal(restarted.findings[0][1].resolvedAt,resolvedAt);
    await assert.rejects(()=>publishDefenderShadow(target,{companyId:company.id,projectionId:success.projectionId,expectedRevision:pointer.revision,actor:'fixture',reason:'handoff rehearsal only'}),/comparison-only/);
    pass('actual legacy edits are pending until strict save; rehearsal refuses unsaved data and preserves saved workflow/timestamps across a fresh reader');

    await patch({assignee:'save-failure'});memory.counter++;
    persistence.onWrite((_sql,params)=>{if(params[0]==='meta')throw Error('simulated final shard failure');});
    const failed=await rehearseDefenderHandoff(args);assert.equal(failed.state,'refused');assert.equal(failed.stage,'flush');assert.match(failed.reason,/shard failure/);
    assert.equal((await disk()).findings[0][1].assignee,'pending-analyst','earlier finding shard rolls back with failed meta write');
    persistence.onWrite(undefined);
    assert.equal((await rehearseDefenderHandoff(args)).state,'rehearsed','retry recovers without undoing the analyst edit');
    globalThis.__vulnPersistBlocked=true;
    const blocked=await rehearseDefenderHandoff(args);assert.equal(blocked.state,'refused');assert.match(blocked.reason,/storage is unavailable/);
    globalThis.__vulnPersistBlocked=false;
    pass('failed/blocked persistence refuses handoff, rolls back partial shards and permits a later retry');

    let release;
    const inFlight=gate.run(async()=>{await new Promise(resolve=>{release=resolve;});modules.store.updateFinding(finding.id,{assignee:'finished-writer'});});
    const busy=await rehearseDefenderHandoff(args);assert.equal(busy.state,'refused');assert.equal(busy.stage,'pause');release();await inFlight;
    assert.equal((await rehearseDefenderHandoff(args)).state,'rehearsed');
    await patch({assignee:'before-race'});
    let raced=false;
    persistence.onWrite(()=>{if(!raced){raced=true;modules.store.updateFinding(finding.id,{assignee:'bypassed-gate'});}});
    const racedSave=await rehearseDefenderHandoff(args);assert.equal(racedSave.state,'refused');assert.match(racedSave.reason,/Memory changed/);
    assert.equal((await disk()).findings[0][1].assignee,'before-race');
    persistence.onWrite(undefined);
    let attempted=false;
    const guarded=await rehearseDefenderHandoff({...args,afterPlan:async()=>{attempted=true;await assert.rejects(()=>patch({assignee:'must-not-write'}),/admission is paused/);}});
    assert.equal(guarded.state,'rehearsed');assert.equal(attempted,true);assert.equal(finding.assignee,'bypassed-gate');
    pass('active writers prevent rehearsal; paused admission rejects new writes and direct mutation during flushing is detected');

    const afterPlan=await rehearseDefenderHandoff({...args,afterPlan:()=>modules.store.updateFinding(finding.id,{status:'Risk Accepted'})});
    assert.equal(afterPlan.state,'refused');assert.match(afterPlan.reason,/Memory changed/);
    let interruptedProjection;
    const duringBuild=await rehearseDefenderHandoff({...args,afterBatch:event=>{interruptedProjection=event.projectionId;modules.store.updateFinding(finding.id,{assignee:'late-edit'});}});
    assert.equal(duringBuild.state,'refused');assert.match(duringBuild.reason,/Memory changed/);
    assert.equal((await target.query('SELECT state FROM defender_shadow_generations WHERE projection_id=$1',[interruptedProjection])).rows[0].state,'failed');
    assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
    const resumed=await patch({assignee:'legacy-resumed'});assert.equal(resumed.assignee,'legacy-resumed');
    pass('edits during planning/writing abort rehearsal, failed candidates remain unreadable and legacy admission resumes without publication');
  }finally{
    persistence.onWrite(undefined);globalThis.__vulnPersistBlocked=false;
    globalThis.__vulnStore=baseline;await modules.store.flushNow({throwOnError:true});
  }
}
