import {readDefenderRefreshBaseline,checkDefenderRefreshBaseline} from './defender-refresh-baseline.mjs';
import {writeDefenderRefreshCandidate} from './defender-refresh-candidate.mjs';
import {buildDefenderShadowReads} from './defender-shadow-reads.mjs';
import {readDefenderWorkflow,defenderWorkflowUnchanged} from './defender-workflow-edits.mjs';
import {applyDefenderWorkflow} from './defender-workflow-overlay.mjs';
import {handoffBaselineDigest} from './defender-handoff-evidence.mjs';
// Explicit offline dependency injection. No runtime import, hydration, scheduler
// or publication control. A successful check is NOT permission to publish.
export async function buildDefenderRefresh(source,target,companyId,{prepare,capture,afterCollect,afterPlan,afterBatch,withWorkflow=false,handoffAttemptId}={}){
  if(typeof prepare!=='function'||typeof capture!=='function')throw Error('Explicit candidate planner and assessment capture required');
  if(handoffAttemptId!==undefined&&(!withWorkflow||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(handoffAttemptId)))throw Error('Handoff requires explicit attempt and workflow snapshot');
  const started=Date.now(),input=await readDefenderRefreshBaseline(source,companyId);
  const collectedMs=Date.now()-started;await afterCollect?.(input);
  const assessment=capture(companyId,[...input.baseline.findings.map(f=>f.cve),...input.source.snapshot.findings.map(f=>f.cve)],input.controls);
  const workflow=withWorkflow?await readDefenderWorkflow(target,companyId):null;
  let candidate=prepare({...input,assessmentContext:assessment.digest},assessment.score);
  if(workflow){const applied=applyDefenderWorkflow(candidate,workflow);
    if(applied.state==='conflict')return {...applied,state:'workflow-conflict',publicationAllowed:false};candidate=applied.candidate;}
  candidate.baselineFence=input.baselineFence;candidate.assessmentEvidence=assessment.evidence;
  if(handoffAttemptId)candidate.handoff={version:1,attemptId:handoffAttemptId,workflowRevision:workflow.revision,
    baselineDigest:handoffBaselineDigest({company:input.company,...input.baseline,controls:input.controls})};
  const plannedMs=Date.now()-started-collectedMs;await afterPlan?.(candidate,input);
  if(!(await checkDefenderRefreshBaseline(source,input.baselineFence)).unchanged||(workflow&&!await defenderWorkflowUnchanged(target,workflow)))return {state:'stale',phase:'before-write',publicationAllowed:false};
  const built=await writeDefenderRefreshCandidate(target,candidate,{afterBatch});
  const baseMs=Date.now()-started-collectedMs-plannedMs;
  await buildDefenderShadowReads(target,companyId,built.projectionId);
  const unchanged=(await checkDefenderRefreshBaseline(source,input.baselineFence)).unchanged&&(!workflow||await defenderWorkflowUnchanged(target,workflow));
  return {...built,state:unchanged?'comparison-only':'stale',phase:'after-build',publicationAllowed:false,
    checkScope:'persisted-state-only',...(workflow?{workflowRevision:workflow.revision}:{}),timings:{collectedMs,plannedMs,baseMs,totalMs:Date.now()-started}};
}
