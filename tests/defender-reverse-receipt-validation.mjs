import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {legacyPersistenceFixture} from './legacy-persistence-fixture.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {initializeWriterOwnership,readWriterOwnership,transitionWriterOwnership,completeVerifiedOwnership,defenderWriterKinds} from '../lib/db/defender-writer-ownership.mjs';
import {editOwnedDefenderWorkflow} from '../lib/db/defender-workflow-edits.mjs';
import {prepareOwnedReverseExport,verifyOwnedReverseRestore,reverseSnapshotDigest} from '../lib/db/defender-reverse-receipt.mjs';
import {applyDefenderWorkflowExport} from '../lib/db/defender-workflow-export.mjs';
import {readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
const json=v=>JSON.parse(JSON.stringify(v));
export async function verifyReverseReceipts({source,target,peer,pool,newClient,company,run,modules,pass}){
  await target.query(await readFile('docs/sql/defender-shadow-reverse-receipts.sql','utf8'));
  const persistence=await legacyPersistenceFixture(pool),original=json(await persistence.persist.loadSnapshot()),snapshot=json(original);
  const customer={...snapshot.companies.find(([id])=>id===company.id)[1],id:'CO-REVERSE',name:'Reverse receipt fixture'},sourceRun=randomUUID();
  snapshot.companies.push([customer.id,customer]);snapshot.meta.defenderGenerations[customer.id]=sourceRun;
  const finding=json(snapshot.findings.find(([,f])=>f.companyId===company.id&&f.defender)[1]);
  finding.id+='-REVERSE';finding.companyId=customer.id;finding.defender.runId=sourceRun;finding.status='Open';finding.resolvedAt=null;finding.assignee=null;
  snapshot.findings.push([finding.id,finding]);
  for(const [,asset] of original.assets.filter(([,a])=>a.companyId===company.id)){
    const copy={...json(asset),id:asset.id+'-REVERSE',companyId:customer.id};snapshot.assets.push([copy.id,copy]);
  }
  await source.query(`INSERT INTO defender_connections(company_id,tenant_id,client_id,secret,updated_by,current_run,last_success_at)
    SELECT $1,'fixture-reverse-tenant',client_id,secret,updated_by,$2,last_success_at FROM defender_connections WHERE company_id=$3`,[customer.id,sourceRun,company.id]);
  await source.query(`INSERT INTO defender_import_runs(id,company_id,revision,status,phase,actor,finished_at,summary)
    SELECT $1,$2,revision,status,phase,actor,finished_at,summary FROM defender_import_runs WHERE id=$3`,[sourceRun,customer.id,run]);
  await source.query('INSERT INTO defender_devices SELECT $1,device_id,record FROM defender_devices WHERE run_id=$2',[sourceRun,run]);
  // Column order is the same explicit fixture layout used by the source reader suite.
  await source.query('INSERT INTO defender_records SELECT $1,source_id,device_id,cve,severity,cvss,record FROM defender_records WHERE run_id=$2',[sourceRun,run]);
  const context={companyId:customer.id,actor:'fixture',reason:'reverse receipt rehearsal'},buildOptions={prepare:modules.candidate.prepareDefenderRefreshCandidate,capture:modules.assessment.captureDefenderRefreshAssessment,withWorkflow:true};
  const read=()=>readWriterOwnership(target,customer.id);
  const change=async r=>transitionWriterOwnership(target,{...context,expectedRevision:(await read()).revision,...r});
  const register=async(owner,processId)=>change({action:'register',owner,processId,inventoryVersion:1,writerKinds:defenderWriterKinds});
  try{
    await persistence.persist.saveSnapshot(snapshot);
    await buildDefenderRefresh(source,target,customer.id,buildOptions);await initializeWriterOwnership(target,context);
    const legacyId=randomUUID(),forwardId=randomUUID();await register('legacy',legacyId);await change({action:'begin',attemptId:forwardId});
    const selected=await buildDefenderRefresh(source,target,customer.id,{...buildOptions,handoffAttemptId:forwardId});
    const proof=(await target.query('SELECT evidence FROM defender_shadow_refresh_candidates WHERE projection_id=$1',[selected.projectionId])).rows[0].evidence;
    await change({action:'ack',attemptId:forwardId,processId:legacyId,pendingWrites:0,strictFlush:true,baselineDigest:proof.handoff.baselineDigest});
    await completeVerifiedOwnership(source,target,{...context,expectedRevision:(await read()).revision,attemptId:forwardId,projectionId:selected.projectionId});
    const sqlId=randomUUID(),registered=await register('sql',sqlId);
    await editOwnedDefenderWorkflow(target,{...context,findingId:finding.id,projectionId:selected.projectionId,expectedRevision:0,patch:{status:'Resolved',assignee:'reverse-analyst'}},
      {companyId:customer.id,processId:sqlId,owner:'sql',epoch:registered.epoch});
    const attemptId=randomUUID();await change({action:'begin',attemptId});
    let request={...context,attemptId,expectedRevision:(await read()).revision};
    await assert.rejects(()=>prepareOwnedReverseExport(source,target,request),/acknowledge drain/);
    await change({action:'ack',attemptId,processId:sqlId,pendingWrites:0,strictFlush:true,baselineDigest:proof.handoff.baselineDigest});
    request={...request,expectedRevision:(await read()).revision};
    await assert.rejects(()=>prepareOwnedReverseExport(source,target,{...request,projectionId:randomUUID()}),/no declared evidence/);
    await assert.rejects(()=>prepareOwnedReverseExport(source,target,request,{afterCollect:()=>source.query("UPDATE vuln_store SET data=data WHERE key='meta'")}),/changed during reverse/);
    await assert.rejects(()=>prepareOwnedReverseExport(source,target,request,{afterCollect:()=>peer.query('UPDATE defender_workflow_heads SET revision=revision+1 WHERE company_id=$1',[customer.id])}),/workflow changed/);
    assert.equal((await target.query('SELECT count(*)::int n FROM defender_reverse_exports')).rows[0].n,0);
    const exported=await prepareOwnedReverseExport(source,target,request);
    assert.equal(exported.projection_id,selected.projectionId);assert.equal(exported.artifact.activationAllowed,false);
    assert.deepEqual(await prepareOwnedReverseExport(source,target,request),exported);
    assert.equal(exported.baseline_digest,reverseSnapshotDigest(snapshot));
    const expected=applyDefenderWorkflowExport(snapshot,exported.artifact);
    assert.equal(exported.expected_digest,reverseSnapshotDigest(expected));
    const ownership=await read(),publication=await readDefenderPublication(target,customer.id);
    pass('reverse artifact is durably bound to the acknowledged ownership-selected generation; source/workflow drift and supplied generation overrides are refused');

    const receiptCount=async()=>Number((await target.query('SELECT count(*) n FROM defender_reverse_receipts')).rows[0].n);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request),/does not match/);assert.equal(await receiptCount(),0);
    persistence.onWrite(()=>{throw Error('interrupted legacy restore');});
    await assert.rejects(()=>persistence.persist.saveSnapshot(expected),/interrupted legacy/);persistence.onWrite(undefined);
    assert.equal(reverseSnapshotDigest(json(await (await persistence.fresh()).loadSnapshot())),exported.baseline_digest);
    await persistence.persist.saveSnapshot(expected);
    assert.equal(reverseSnapshotDigest(json(await (await persistence.fresh()).loadSnapshot())),exported.expected_digest);
    // Lose the receipt transaction after its INSERT, leaving the legacy save
    // committed. A fresh connection must recover by reading, not rewriting it.
    const crashing=await newClient();crashing.on('error',()=>{});
    await assert.rejects(()=>verifyOwnedReverseRestore(source,crashing,request,{beforeCommit:async()=>{
      await peer.query('SELECT pg_terminate_backend($1)',[crashing.processID]);await new Promise(resolve=>setTimeout(resolve,20));
    }}));await crashing.end().catch(()=>{});assert.equal(await receiptCount(),0);
    const restarted=await newClient();let receipt;
    try{receipt=await verifyOwnedReverseRestore(source,restarted,request);}finally{await restarted.end();}
    assert.equal(receipt.restored_digest,exported.expected_digest);assert.equal(await receiptCount(),1);
    assert.deepEqual(await verifyOwnedReverseRestore(source,target,request),receipt);assert.equal(await receiptCount(),1);
    assert.deepEqual(await read(),ownership);assert.deepEqual(await readDefenderPublication(target,customer.id),publication);
    pass('failed save and lost receipt connection recover safely: independent fresh reads confirm the saved snapshot and retry records one receipt without changing ownership/publication');

    const altered=json(expected);altered.settings.reverseFixture=true;await persistence.persist.saveSnapshot(altered);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request),/does not match/);await persistence.persist.saveSnapshot(expected);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request,{afterRead:()=>source.query("UPDATE vuln_store SET data=data WHERE key='meta'")}),/changed during reverse/);
    await source.query('UPDATE defender_connections SET revision=revision+1 WHERE company_id=$1',[customer.id]);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request),/Complete reverse source/);
    await source.query('UPDATE defender_connections SET revision=revision-1 WHERE company_id=$1',[customer.id]);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request),/does not match/,'reverted source value still has a changed transaction version');
    for(const table of ['defender_reverse_exports','defender_reverse_receipts'])for(const sql of [`UPDATE ${table} SET actor='tampered'`,`DELETE FROM ${table}`,`TRUNCATE ${table}`])await assert.rejects(()=>target.query(sql));
    await assert.rejects(()=>completeVerifiedOwnership(source,target,{...request,projectionId:selected.projectionId}),/reverse export/);
    await change({action:'abort',attemptId});
    assert.equal((await read()).data.lastCompleted.projectionId,selected.projectionId);
    await assert.rejects(()=>verifyOwnedReverseRestore(source,target,request),/attempt changed/);
    await assert.rejects(()=>prepareOwnedReverseExport(source,target,request),/attempt changed/);
    assert.equal(await receiptCount(),1);
    pass('changed legacy metadata/source and stale attempts cannot reuse a receipt; evidence rejects mutation and reversal stays blocked while abort retains the selected generation');
  }finally{persistence.onWrite(undefined);await persistence.persist.saveSnapshot(original);}
}
