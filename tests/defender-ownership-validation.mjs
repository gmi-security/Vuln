import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {initializeWriterOwnership,readWriterOwnership,transitionWriterOwnership,completeVerifiedOwnership,withOwnershipWrite,defenderWriterKinds} from '../lib/db/defender-writer-ownership.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {editOwnedDefenderWorkflow,editDefenderWorkflow,readDefenderWorkflow} from '../lib/db/defender-workflow-edits.mjs';
import {readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
export async function verifyWriterOwnership({source,target,peer,newClient,company,modules,first,pass}){
  await target.query(await readFile('docs/sql/defender-shadow-ownership.sql','utf8'));
  await target.query('CREATE TABLE ownership_fixture_writes(value text)');
  const context={companyId:company.id,actor:'fixture operator',reason:'isolated ownership test'},p1=randomUUID(),p2=randomUUID();
  const pointer=await readDefenderPublication(target,company.id);
  const read=client=>readWriterOwnership(client??target,company.id);
  const change=async(r,client=target)=>transitionWriterOwnership(client,{...context,expectedRevision:(await read(client)).revision,...r});
  const register=(id,owner='legacy')=>change({action:'register',processId:id,owner,inventoryVersion:1,writerKinds:defenderWriterKinds});
  const token=(state,processId,owner=state.phase)=>({companyId:company.id,processId,owner,epoch:state.epoch});
  const write=(client,t,value)=>withOwnershipWrite(client,t,c=>c.query('INSERT INTO ownership_fixture_writes VALUES($1)',[value]));
  assert.equal(await read(),null);
  await assert.rejects(()=>write(target,{companyId:company.id,processId:p1,owner:'legacy',epoch:0},'missing'),/fenced/);
  await assert.rejects(()=>initializeWriterOwnership(source,context),/Disposable target/);
  await assert.rejects(()=>initializeWriterOwnership(target,{...context,companyId:'CO-MISSING'}),/Verified customer/);
  const prior=(await readDefenderWorkflow(target,company.id)).rows[0];
  let releaseLegacy,legacyEntered;const legacyReady=new Promise(resolve=>{legacyEntered=resolve;});
  const pendingLegacy=editDefenderWorkflow(target,{...context,findingId:prior.finding_id,projectionId:first.projectionId,expectedRevision:Number(prior.revision),patch:{assignee:'before-ownership'}},
    {beforeCommit:async()=>{legacyEntered();await new Promise(resolve=>{releaseLegacy=resolve;});}});
  await legacyReady;const initializing=initializeWriterOwnership(peer,context),initObserver=await newClient();
  try{
    let waiting=false;for(let i=0;i<30&&!waiting;i++){
      waiting=(await initObserver.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[peer.processID])).rows[0]?.wait_event_type==='Lock';
      if(!waiting)await new Promise(resolve=>setTimeout(resolve,10));
    }assert.equal(waiting,true);releaseLegacy();await pendingLegacy;await initializing;
  }finally{releaseLegacy?.();await initObserver.end();}
  pass('first ownership initialization waits for an already admitted unguarded workflow edit');
  await assert.rejects(()=>change({action:'register',processId:p1,owner:'legacy',inventoryVersion:1,writerKinds:[]}),/inventory/);
  let s=await register(p1);const legacyToken=token(s,p1);await register(p2);await write(target,legacyToken,'legacy-write');
  const unchanged=await read();await initializeWriterOwnership(target,context);assert.deepEqual(await read(),unchanged,'restart initialization cannot reset ownership');
  pass('ownership is explicit and customer scoped; incomplete writer inventory and missing ownership refuse writes');

  // A handoff transaction waits behind a currently admitted SQL write, then
  // fences both old process tokens. Verify the actual PostgreSQL wait state.
  let release,entered;const enteredPromise=new Promise(resolve=>{entered=resolve;});
  const active=withOwnershipWrite(target,legacyToken,async c=>{await c.query("INSERT INTO ownership_fixture_writes VALUES('in-flight')");entered();await new Promise(resolve=>{release=resolve;});});
  await enteredPromise;
  const attemptId=randomUUID(),before=await read(peer);
  const beginning=transitionWriterOwnership(peer,{...context,expectedRevision:before.revision,action:'begin',attemptId});
  const observer=await newClient();
  try{
    let waiting=false;for(let i=0;i<30&&!waiting;i++){
      const row=(await observer.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[peer.processID])).rows[0];waiting=row?.wait_event_type==='Lock';
      if(!waiting)await new Promise(resolve=>setTimeout(resolve,10));
    }assert.equal(waiting,true,'transition waits for admitted writer transaction');release();await active;s=await beginning;
  }finally{release?.();await observer.end();}
  assert.equal(s.phase,'draining');await assert.rejects(()=>write(target,legacyToken,'stale'),/fenced/);
  await assert.rejects(()=>register(randomUUID()),/not active/);
  const options={prepare:modules.candidate.prepareDefenderRefreshCandidate,capture:modules.assessment.captureDefenderRefreshAssessment,withWorkflow:true,handoffAttemptId:attemptId};
  let candidate=await buildDefenderRefresh(source,target,company.id,options);assert.equal(candidate.state,'comparison-only');
  const evidenceRow=(await target.query('SELECT evidence FROM defender_shadow_refresh_candidates WHERE projection_id=$1',[candidate.projectionId])).rows[0].evidence;
  const hash=evidenceRow.handoff.baselineDigest;
  const evidence={attemptId,projectionId:candidate.projectionId};
  const complete=async(overrides={},client=target)=>completeVerifiedOwnership(source,client,{...context,expectedRevision:(await read(client)).revision,...evidence,...overrides});
  await assert.rejects(()=>change({action:'finish',attemptId,baselineDigest:hash,candidateDigest:hash,workflowRevision:0}),/verified candidate evidence/);
  await assert.rejects(()=>complete({candidateDigest:hash}),/not declared/);
  await assert.rejects(()=>complete({projectionId:first.projectionId}),/Matching verified/);
  await assert.rejects(()=>complete({attemptId:randomUUID()}),/Matching verified/);
  await assert.rejects(()=>complete(),/acknowledge drain/);
  await change({action:'ack',attemptId,processId:p1,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  await assert.rejects(()=>complete(),/acknowledge drain/);
  const restarted=await newClient();try{assert.equal((await read(restarted)).phase,'draining');await assert.rejects(()=>write(restarted,legacyToken,'restart'),/fenced/);}finally{await restarted.end();}
  await change({action:'ack',attemptId,processId:p2,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  await source.query("UPDATE vuln_store SET data=data WHERE key='meta'");
  await assert.rejects(()=>complete(),/source or baseline changed/);
  candidate=await buildDefenderRefresh(source,target,company.id,options);evidence.projectionId=candidate.projectionId;
  // Simulate a writer bypassing the ownership protocol; completion must still
  // detect workflow revision drift from independently stored candidate evidence.
  await target.query('UPDATE defender_workflow_heads SET revision=revision+1 WHERE company_id=$1',[company.id]);
  await assert.rejects(()=>complete(),/Workflow changed/);
  candidate=await buildDefenderRefresh(source,target,company.id,options);evidence.projectionId=candidate.projectionId;
  const version=(await read()).revision;
  const outcomes=await Promise.allSettled([target,peer].map(client=>completeVerifiedOwnership(source,client,{...context,...evidence,expectedRevision:version})));
  assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);assert.match(outcomes.find(r=>r.status==='rejected').reason.message,/Ownership changed/);
  s=await read();assert.equal(s.phase,'sql');await assert.rejects(()=>write(target,legacyToken,'legacy-after-switch'),/fenced/);
  pass('active writes drain under real locks; restart stays paused, every process must acknowledge, and competing switches yield one winner');

  const sqlProcess=randomUUID();s=await register(sqlProcess,'sql');const sqlToken=token(s,sqlProcess);await write(target,sqlToken,'sql-write');
  const reverseId=randomUUID();await change({action:'begin',attemptId:reverseId});
  await assert.rejects(()=>write(target,sqlToken,'sql-during-reverse'),/fenced/);
  await change({action:'ack',attemptId:reverseId,processId:sqlProcess,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  await assert.rejects(()=>complete({attemptId:reverseId}),/reverse export/);
  // Terminate a connection after its ownership update and audit insert but
  // before commit. A new connection must see the paused state and old audit.
  const crashing=await newClient(),saved=await read(),auditCount=Number((await target.query('SELECT count(*) n FROM defender_writer_ownership_audit')).rows[0].n);
  crashing.on('error',()=>{});
  await assert.rejects(()=>transitionWriterOwnership(crashing,{...context,action:'abort',attemptId:reverseId,expectedRevision:saved.revision},{beforeCommit:async()=>{
    await peer.query('SELECT pg_terminate_backend($1)',[crashing.processID]);
    await new Promise(resolve=>setTimeout(resolve,20));
  }}));await crashing.end().catch(()=>{});
  assert.deepEqual(await read(),saved);assert.equal(Number((await target.query('SELECT count(*) n FROM defender_writer_ownership_audit')).rows[0].n),auditCount);
  s=await change({action:'abort',attemptId:reverseId});assert.equal(s.phase,'sql');await assert.rejects(()=>write(target,sqlToken,'old-sql'),/fenced/);
  const newProcess=randomUUID();s=await register(newProcess,'sql');const newToken=token(s,newProcess);await write(target,newToken,'resumed-write');
  pass('reverse completion is blocked without verified export; lost connection rolls back transition/audit and abort invalidates old tokens');

  const workflow=await readDefenderWorkflow(target,company.id),row=workflow.rows[0];
  const request={...context,findingId:row.finding_id,projectionId:first.projectionId,expectedRevision:Number(row.revision),patch:{assignee:'ownership-analyst'}};
  await assert.rejects(()=>editDefenderWorkflow(target,request),/Ownership token required/);
  await assert.rejects(()=>editOwnedDefenderWorkflow(target,request,{...newToken,companyId:'CO-OTHER'}),/Matching SQL/);
  await assert.rejects(()=>editOwnedDefenderWorkflow(target,request,sqlToken),/fenced/);
  const notices=[];const notice=n=>notices.push(n.message);target.on('notice',notice);
  const auditBefore=Number((await target.query('SELECT count(*) n FROM defender_workflow_events')).rows[0].n);
  await assert.rejects(()=>editOwnedDefenderWorkflow(target,request,newToken,{beforeCommit(){throw Error('edit interrupted');}}),/edit interrupted/);
  assert.deepEqual(await readDefenderWorkflow(target,company.id),workflow);
  assert.equal(Number((await target.query('SELECT count(*) n FROM defender_workflow_events')).rows[0].n),auditBefore);
  const edited=await editOwnedDefenderWorkflow(target,request,newToken);assert.equal(edited.changed,true);
  assert.equal(Number((await target.query('SELECT count(*) n FROM defender_workflow_events')).rows[0].n),auditBefore+1);
  assert.equal((await readDefenderWorkflow(target,company.id)).rows[0].patches.assignee.value,'ownership-analyst');
  await assert.rejects(()=>editOwnedDefenderWorkflow(target,request,newToken),/Workflow changed/);
  target.removeListener('notice',notice);assert.ok(!notices.some(n=>/transaction.*progress|no transaction/i.test(n)),'no nested BEGIN/COMMIT');
  pass('actual owned workflow edits commit once with audit; wrong/stale tokens, old writer bypass and interrupted edits leave no changes');

  let releaseEdit,editEntered;const editReady=new Promise(resolve=>{editEntered=resolve;});
  const editing=editOwnedDefenderWorkflow(target,{...request,expectedRevision:edited.revision,patch:{assignee:'before-drain'}},newToken,{beforeCommit:async()=>{editEntered();await new Promise(resolve=>{releaseEdit=resolve;});}});
  await editReady;const ownedAttempt=randomUUID(),ownedVersion=(await read(peer)).revision;
  const pausing=transitionWriterOwnership(peer,{...context,expectedRevision:ownedVersion,action:'begin',attemptId:ownedAttempt});
  const observing=await newClient();try{
    let waiting=false;for(let i=0;i<30&&!waiting;i++){
      waiting=(await observing.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[peer.processID])).rows[0]?.wait_event_type==='Lock';
      if(!waiting)await new Promise(resolve=>setTimeout(resolve,10));
    }assert.equal(waiting,true);releaseEdit();await editing;await pausing;
  }finally{releaseEdit?.();await observing.end();}
  assert.equal((await readDefenderWorkflow(target,company.id)).rows[0].patches.assignee.value,'before-drain');
  await assert.rejects(()=>editOwnedDefenderWorkflow(target,{...request,expectedRevision:edited.revision+1},newToken),/fenced/);
  await change({action:'abort',attemptId:ownedAttempt});
  pass('ownership transition waits for the actual workflow edit transaction, then rejects later edits from its old token');

  for(const sql of ['DELETE FROM defender_writer_ownership','TRUNCATE defender_writer_ownership',"UPDATE defender_writer_ownership SET phase='legacy',epoch=epoch+1,revision=revision+1",'DELETE FROM defender_writer_ownership_audit','UPDATE defender_writer_ownership_audit SET revision=revision+1','TRUNCATE defender_writer_ownership_audit'])await assert.rejects(()=>target.query(sql));
  const audit=(await target.query('SELECT before_state,after_state FROM defender_writer_ownership_audit ORDER BY revision')).rows;
  assert.equal(audit[0].before_state,null);for(let i=1;i<audit.length;i++)assert.deepEqual(audit[i].before_state,audit[i-1].after_state);
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  assert.deepEqual((await target.query('SELECT value FROM ownership_fixture_writes ORDER BY value')).rows.map(r=>r.value),['in-flight','legacy-write','resumed-write','sql-write']);
  pass('ownership audit rejects tampering, denied writes leave no side effects, and real publication remains unchanged');
}
