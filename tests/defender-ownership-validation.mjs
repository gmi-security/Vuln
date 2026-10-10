import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {initializeWriterOwnership,readWriterOwnership,transitionWriterOwnership,withOwnershipWrite,defenderWriterKinds} from '../lib/db/defender-writer-ownership.mjs';
import {readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
export async function verifyWriterOwnership({source,target,peer,newClient,company,pass}){
  await target.query(await readFile('docs/sql/defender-shadow-ownership.sql','utf8'));
  await target.query('CREATE TABLE ownership_fixture_writes(value text)');
  const context={companyId:company.id,actor:'fixture operator',reason:'isolated ownership test'},p1=randomUUID(),p2=randomUUID(),hash='a'.repeat(64);
  const pointer=await readDefenderPublication(target,company.id);
  const read=client=>readWriterOwnership(client??target,company.id);
  const change=async(r,client=target)=>transitionWriterOwnership(client,{...context,expectedRevision:(await read(client)).revision,...r});
  const register=(id,owner='legacy')=>change({action:'register',processId:id,owner,inventoryVersion:1,writerKinds:defenderWriterKinds});
  const token=(state,processId,owner=state.phase)=>({companyId:company.id,processId,owner,epoch:state.epoch});
  const write=(client,t,value)=>withOwnershipWrite(client,t,c=>c.query('INSERT INTO ownership_fixture_writes VALUES($1)',[value]));
  const head=async()=>Number((await target.query('SELECT revision FROM defender_workflow_heads WHERE company_id=$1',[company.id])).rows[0].revision);
  assert.equal(await read(),null);
  await assert.rejects(()=>write(target,{companyId:company.id,processId:p1,owner:'legacy',epoch:0},'missing'),/fenced/);
  await assert.rejects(()=>initializeWriterOwnership(source,context),/Disposable target/);
  await assert.rejects(()=>initializeWriterOwnership(target,{...context,companyId:'CO-MISSING'}),/Verified customer/);
  await initializeWriterOwnership(target,context);
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
  const evidence={action:'finish',attemptId,baselineDigest:hash,candidateDigest:hash,workflowRevision:await head()};
  await assert.rejects(()=>change(evidence),/acknowledge drain/);
  await change({action:'ack',attemptId,processId:p1,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  await assert.rejects(()=>change(evidence),/acknowledge drain/);
  const restarted=await newClient();try{assert.equal((await read(restarted)).phase,'draining');await assert.rejects(()=>write(restarted,legacyToken,'restart'),/fenced/);}finally{await restarted.end();}
  await change({action:'ack',attemptId,processId:p2,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  await assert.rejects(()=>change({...evidence,workflowRevision:0}),/Workflow changed/);
  const version=(await read()).revision;
  const outcomes=await Promise.allSettled([target,peer].map(client=>transitionWriterOwnership(client,{...context,...evidence,expectedRevision:version})));
  assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);assert.match(outcomes.find(r=>r.status==='rejected').reason.message,/Ownership changed/);
  s=await read();assert.equal(s.phase,'sql');await assert.rejects(()=>write(target,legacyToken,'legacy-after-switch'),/fenced/);
  pass('active writes drain under real locks; restart stays paused, every process must acknowledge, and competing switches yield one winner');

  const sqlProcess=randomUUID();s=await register(sqlProcess,'sql');const sqlToken=token(s,sqlProcess);await write(target,sqlToken,'sql-write');
  const reverseId=randomUUID();await change({action:'begin',attemptId:reverseId});
  await assert.rejects(()=>write(target,sqlToken,'sql-during-reverse'),/fenced/);
  await change({action:'ack',attemptId:reverseId,processId:sqlProcess,pendingWrites:0,strictFlush:true,baselineDigest:hash});
  const reverse={action:'finish',attemptId:reverseId,baselineDigest:hash,candidateDigest:hash,workflowRevision:await head()};
  await assert.rejects(()=>change(reverse),/reverse export/);
  // Terminate a connection after its ownership update and audit insert but
  // before commit. A new connection must see the paused state and old audit.
  const crashing=await newClient(),saved=await read(),auditCount=Number((await target.query('SELECT count(*) n FROM defender_writer_ownership_audit')).rows[0].n);
  crashing.on('error',()=>{});
  await assert.rejects(()=>transitionWriterOwnership(crashing,{...context,...reverse,reverseExportDigest:hash,expectedRevision:saved.revision},{beforeCommit:async()=>{
    await peer.query('SELECT pg_terminate_backend($1)',[crashing.processID]);
    await new Promise(resolve=>setTimeout(resolve,20));
  }}));await crashing.end().catch(()=>{});
  assert.deepEqual(await read(),saved);assert.equal(Number((await target.query('SELECT count(*) n FROM defender_writer_ownership_audit')).rows[0].n),auditCount);
  s=await change({...reverse,reverseExportDigest:hash});assert.equal(s.phase,'legacy');await assert.rejects(()=>write(target,sqlToken,'old-sql'),/fenced/);
  const newProcess=randomUUID();s=await register(newProcess);const newToken=token(s,newProcess);await write(target,newToken,'reversed-write');
  const abortedId=randomUUID();await change({action:'begin',attemptId:abortedId});await change({action:'abort',attemptId:abortedId});
  await assert.rejects(()=>write(target,newToken,'pre-abort-token'),/fenced/);assert.equal((await read()).phase,'legacy');
  pass('reverse handoff requires exported workflow; lost connection rolls back transition/audit; abort and reversal invalidate old tokens');

  for(const sql of ['DELETE FROM defender_writer_ownership','TRUNCATE defender_writer_ownership',"UPDATE defender_writer_ownership SET phase='sql',epoch=epoch+1,revision=revision+1",'DELETE FROM defender_writer_ownership_audit','UPDATE defender_writer_ownership_audit SET revision=revision+1','TRUNCATE defender_writer_ownership_audit'])await assert.rejects(()=>target.query(sql));
  const audit=(await target.query('SELECT before_state,after_state FROM defender_writer_ownership_audit ORDER BY revision')).rows;
  assert.equal(audit[0].before_state,null);for(let i=1;i<audit.length;i++)assert.deepEqual(audit[i].before_state,audit[i-1].after_state);
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  assert.deepEqual((await target.query('SELECT value FROM ownership_fixture_writes ORDER BY value')).rows.map(r=>r.value),['in-flight','legacy-write','reversed-write','sql-write']);
  pass('ownership audit rejects tampering, denied writes leave no side effects, and real publication remains unchanged');
}
