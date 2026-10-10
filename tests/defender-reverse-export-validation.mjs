import assert from 'node:assert/strict';
import {legacyPersistenceFixture} from './legacy-persistence-fixture.mjs';
import {collectDefenderWorkflowExport,applyDefenderWorkflowExport} from '../lib/db/defender-workflow-export.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {readDefenderWorkflow} from '../lib/db/defender-workflow-edits.mjs';
import {readDefenderPublication,publishDefenderShadow} from '../lib/db/defender-shadow-publication.mjs';
import {readWriterOwnership} from '../lib/db/defender-writer-ownership.mjs';
const json=v=>JSON.parse(JSON.stringify(v));
const sorted=s=>{const copy=json(s);for(const key of ['companies','folders','scans','findings','assets','compensatingControls','identityAliases'])if(Array.isArray(copy[key]))copy[key].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);return copy;};
export async function verifyReverseExport({source,target,pool,exportPool,company,run,modules,pass}){
  const legacy=await legacyPersistenceFixture(pool),receiver=await legacyPersistenceFixture(exportPool);
  const original=json(await legacy.persist.loadSnapshot()),snapshot=json(original);
  snapshot.meta.defenderGenerations[company.id]=run;
  const own=snapshot.findings.find(([,f])=>f.companyId===company.id&&f.defender)[1];
  snapshot.companies.push(['CO-UNTOUCHED',{id:'CO-UNTOUCHED',name:'Other fixture'}]);
  const unrelated={...json(own),id:'OTHER-FINDING',companyId:'CO-UNTOUCHED',assignee:'other-analyst'};
  const scanner={...json(own),id:'OWN-NESSUS',connector:'nessus'};delete scanner.defender;
  snapshot.findings.push([unrelated.id,unrelated],[scanner.id,scanner]);
  const pointer=await readDefenderPublication(target,company.id),ownership=await readWriterOwnership(target,company.id);
  try{
    await legacy.persist.saveSnapshot(snapshot);
    const built=await buildDefenderRefresh(source,target,company.id,{prepare:modules.candidate.prepareDefenderRefreshCandidate,capture:modules.assessment.captureDefenderRefreshAssessment,withWorkflow:true});
    assert.equal(built.state,'comparison-only');
    const artifact=await collectDefenderWorkflowExport(source,target,company.id,built.projectionId);
    assert.equal(artifact.activationAllowed,false);assert.equal(artifact.changes.length,1);
    const exported=applyDefenderWorkflowExport(snapshot,json(artifact)),workflow=await readDefenderWorkflow(target,company.id);
    const restored=exported.findings.find(([id])=>id===own.id)[1];
    assert.equal(restored.status,workflow.rows[0].patches.status.value);assert.equal(restored.resolvedAt,workflow.rows[0].patches.status.resolvedAt);
    assert.equal(restored.assignee,workflow.rows[0].patches.assignee.value);
    await receiver.persist.saveSnapshot(exported);
    const loaded=await (await receiver.fresh()).loadSnapshot();assert.deepEqual(sorted(loaded),sorted(exported));
    assert.deepEqual(json(loaded.findings.find(([id])=>id===unrelated.id)[1]),unrelated);
    assert.deepEqual(json(loaded.findings.find(([id])=>id===scanner.id)[1]),scanner);
    pass('workflow reverse artifact round-trips through the actual legacy writer/fresh reader with original resolution time and untouched customers/scanners');

    await assert.rejects(()=>collectDefenderWorkflowExport(source,target,'CO-UNTOUCHED',built.projectionId));
    await assert.rejects(()=>collectDefenderWorkflowExport(source,target,company.id,built.projectionId,{afterCollect:()=>source.query("UPDATE vuln_store SET data=data WHERE key='meta'")}),/changed during reverse/);
    await assert.rejects(()=>collectDefenderWorkflowExport(source,target,company.id,built.projectionId,{afterCollect:()=>target.query('UPDATE defender_workflow_heads SET revision=revision+1 WHERE company_id=$1',[company.id])}),/changed during reverse/);
    const changed=json(snapshot);changed.meta.defenderGenerations[company.id]='different-applied-run';await legacy.persist.saveSnapshot(changed);
    await assert.rejects(()=>collectDefenderWorkflowExport(source,target,company.id,built.projectionId),/current and applied source/);
    await legacy.persist.saveSnapshot(snapshot);
    const tampered=json(artifact);tampered.changes[0].value.assignee='not-approved';assert.throws(()=>applyDefenderWorkflowExport(snapshot,tampered),/altered/);
    pass('wrong customer, concurrent source/workflow change, applied-generation mismatch and altered artifact refuse reverse export');

    await receiver.persist.saveSnapshot(snapshot);receiver.onWrite(()=>{throw Error('simulated reverse restore failure');});
    await assert.rejects(()=>receiver.persist.saveSnapshot(exported),/restore failure/);
    assert.deepEqual(sorted(await (await receiver.fresh()).loadSnapshot()),sorted(snapshot));
    receiver.onWrite(undefined);await receiver.persist.saveSnapshot(exported);
    assert.deepEqual(sorted(await (await receiver.fresh()).loadSnapshot()),sorted(exported));
    assert.deepEqual(await readWriterOwnership(target,company.id),ownership);assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
    await assert.rejects(()=>publishDefenderShadow(target,{companyId:company.id,projectionId:built.projectionId,expectedRevision:pointer.revision,actor:'fixture',reason:'export is not activation'}),/comparison-only/);
    pass('failed disposable restore retains the old snapshot, retry succeeds, and export never changes ownership/publication');
  }finally{receiver.onWrite(undefined);await legacy.persist.saveSnapshot(original);}
}
