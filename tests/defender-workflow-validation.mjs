import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {editDefenderWorkflow,readDefenderWorkflow,defenderWorkflowUnchanged} from '../lib/db/defender-workflow-edits.mjs';
import {buildDefenderRefresh} from '../lib/db/defender-refresh-coordinator.mjs';
import {reconstructShadowSql} from '../lib/db/defender-platform-shadow.mjs';
import {publishDefenderShadow,readDefenderPublication} from '../lib/db/defender-shadow-publication.mjs';
export async function verifyDefenderWorkflow({source,target,editor,company,first,modules,pass}){
  await target.query(await readFile('docs/sql/defender-shadow-workflow-edits.sql','utf8'));
  const [finding]=(await target.query(reconstructShadowSql,[company.id,first.projectionId])).rows.map(r=>r.record);
  const pointer=await readDefenderPublication(target,company.id);
  const request={companyId:company.id,findingId:finding.id,projectionId:first.projectionId,expectedRevision:0,patch:{assignee:'reviewer-1'},actor:'test analyst',reason:'test decision'};
  const initial=await readDefenderWorkflow(target,company.id);assert.equal(initial.revision,0);assert.deepEqual(initial.rows,[]);
  await assert.rejects(()=>editDefenderWorkflow(source,request),/Disposable target/);
  await assert.rejects(()=>editDefenderWorkflow(target,{...request,companyId:'CO-OTHER'}),e=>e.status===404);
  await assert.rejects(()=>editDefenderWorkflow(target,{...request,findingId:'missing'}),e=>e.status===404);
  assert.equal((await target.query('SELECT count(*)::int n FROM defender_workflow_heads')).rows[0].n,0);
  await assert.rejects(()=>editDefenderWorkflow(target,request,{beforeCommit(){throw Error('interrupted');}}),/interrupted/);
  assert.deepEqual(await readDefenderWorkflow(target,company.id),initial);
  assert.equal((await target.query('SELECT count(*)::int n FROM defender_workflow_events')).rows[0].n,0);
  const firstEdit=await editDefenderWorkflow(target,request);assert.deepEqual(firstEdit,{changed:true,revision:1,companyRevision:1});
  const saved=await readDefenderWorkflow(target,company.id);assert.equal(saved.rows[0].patches.assignee.value,'reviewer-1');
  assert.equal(await defenderWorkflowUnchanged(target,initial),false);assert.equal(await defenderWorkflowUnchanged(target,saved),true);
  const noop=await editDefenderWorkflow(target,{...request,expectedRevision:1});assert.equal(noop.changed,false);assert.equal(noop.companyRevision,1);
  await assert.rejects(()=>editDefenderWorkflow(target,request),e=>e.status===409);
  pass('workflow scope and target restrictions hold; interrupted writes roll back state/head/audit and stale edits fail');

  const concurrent=await Promise.allSettled([target,editor].map((client,i)=>editDefenderWorkflow(client,{...request,expectedRevision:1,patch:{assignee:`winner-${i}`}})));
  assert.equal(concurrent.filter(r=>r.status==='fulfilled').length,1);assert.equal(concurrent.find(r=>r.status==='rejected').reason.status,409);
  const audit=(await target.query('SELECT * FROM defender_workflow_events ORDER BY company_revision')).rows;
  assert.equal(audit.length,2);assert.equal(audit[0].before_state,null);assert.equal(audit[0].after_state.patches.assignee.value,'reviewer-1');
  assert.deepEqual(audit[1].before_state,audit[0].after_state);assert.equal(audit[1].after_state.revision,2);
  for(const sql of ["UPDATE defender_workflow_events SET actor='tamper'",'DELETE FROM defender_workflow_events',
    'INSERT INTO defender_workflow_events SELECT * FROM defender_workflow_events LIMIT 1'])await assert.rejects(()=>target.query(sql),/append-only/);
  for(const table of ['heads','edits','events'])await assert.rejects(()=>target.query(`TRUNCATE defender_workflow_${table}`));
  await assert.rejects(()=>target.query('UPDATE defender_workflow_edits SET revision=revision+2'),/revision/);
  await assert.rejects(()=>target.query('DELETE FROM defender_workflow_edits'),/deleted/);
  await assert.rejects(()=>target.query('UPDATE defender_workflow_heads SET revision=revision+2'),/revision/);
  pass('two competing edits yield one commit and one conflict; audit is complete and rejects mutation');

  const options={prepare:modules.candidate.prepareDefenderRefreshCandidate,capture:modules.assessment.captureDefenderRefreshAssessment,withWorkflow:true};
  const result=await buildDefenderRefresh(source,target,company.id,options);assert.equal(result.state,'comparison-only');assert.equal(result.workflowRevision,2);
  const rebuilt=(await target.query(reconstructShadowSql,[company.id,result.projectionId])).rows[0].record;
  const now=await readDefenderWorkflow(target,company.id);assert.equal(rebuilt.assignee,now.rows[0].patches.assignee.value);assert.equal(rebuilt.status,finding.status);
  const evidence=(await target.query('SELECT evidence FROM defender_shadow_refresh_candidates WHERE projection_id=$1',[result.projectionId])).rows[0].evidence;
  assert.equal(evidence.workflowRevision,2);assert.equal(evidence.workflowDecisions,1);assert.equal(evidence.workflowDigest.length,64);
  let revision=2;
  const change=async()=>{revision++;await editDefenderWorkflow(editor,{...request,expectedRevision:revision-1,patch:{assignee:`reviewer-${revision}`}});};
  const count=async()=>(await target.query('SELECT count(*)::int n FROM defender_shadow_generations')).rows[0].n;
  const before=await count();
  const stale=await buildDefenderRefresh(source,target,company.id,{...options,afterPlan:change});assert.equal(stale.state,'stale');assert.equal(stale.phase,'before-write');assert.equal(await count(),before);
  const late=await buildDefenderRefresh(source,target,company.id,{...options,afterBatch:change});assert.equal(late.state,'stale');assert.equal(late.phase,'after-build');
  await editDefenderWorkflow(target,{...request,expectedRevision:revision,patch:{status:'Resolved'}});revision++;
  const resolved=await buildDefenderRefresh(source,target,company.id,options);assert.equal(resolved.state,'comparison-only');
  const closed=(await target.query(reconstructShadowSql,[company.id,resolved.projectionId])).rows[0].record;assert.equal(closed.status,'Resolved');assert.ok(closed.resolvedAt);
  // Change the candidate's source observation in isolation to exercise the actual
  // coordinator conflict path without importing or changing live source data.
  const beforeConflict=await count();
  const conflict=await buildDefenderRefresh(source,target,company.id,{...options,prepare:(input,score)=>{
    const c=options.prepare(input,score);return {...c,records:c.records.map(f=>({...f,defender:{...f.defender,runId:'newer-source'}}))};
  }});assert.equal(conflict.state,'workflow-conflict');assert.equal(conflict.publicationAllowed,false);assert.equal(await count(),beforeConflict);
  for(const id of [result.projectionId,late.projectionId,resolved.projectionId])await assert.rejects(()=>publishDefenderShadow(target,{companyId:company.id,projectionId:id,expectedRevision:pointer.revision,actor:'fixture',reason:'still blocked'}),/comparison-only/);
  assert.deepEqual(await readDefenderPublication(target,company.id),pointer);
  pass('refresh overlays preserve decisions, reject concurrent edits and source conflicts, and retain the publication block');
}
