import {readDefenderRefreshBaseline,checkDefenderRefreshBaseline} from './defender-refresh-baseline.mjs';
import {writeDefenderRefreshCandidate} from './defender-refresh-candidate.mjs';
import {buildDefenderShadowReads} from './defender-shadow-reads.mjs';
// Explicit offline dependency injection. No runtime import, hydration, scheduler
// or publication control. A successful check is NOT permission to publish.
export async function buildDefenderRefresh(source,target,companyId,{prepare,capture,afterCollect,afterPlan,afterBatch}={}){
  if(typeof prepare!=='function'||typeof capture!=='function')throw Error('Explicit candidate planner and assessment capture required');
  const started=Date.now(),input=await readDefenderRefreshBaseline(source,companyId);
  const collectedMs=Date.now()-started;await afterCollect?.(input);
  const assessment=capture(companyId,[...input.baseline.findings.map(f=>f.cve),...input.source.snapshot.findings.map(f=>f.cve)],input.controls);
  const candidate=prepare({...input,assessmentContext:assessment.digest},assessment.score);
  candidate.baselineFence=input.baselineFence;candidate.assessmentEvidence=assessment.evidence;
  const plannedMs=Date.now()-started-collectedMs;await afterPlan?.(candidate,input);
  if(!(await checkDefenderRefreshBaseline(source,input.baselineFence)).unchanged)return {state:'stale',phase:'before-write',publicationAllowed:false};
  const built=await writeDefenderRefreshCandidate(target,candidate,{afterBatch});
  const baseMs=Date.now()-started-collectedMs-plannedMs;
  await buildDefenderShadowReads(target,companyId,built.projectionId);
  const unchanged=(await checkDefenderRefreshBaseline(source,input.baselineFence)).unchanged;
  return {...built,state:unchanged?'comparison-only':'stale',phase:'after-build',publicationAllowed:false,
    checkScope:'persisted-state-only',timings:{collectedMs,plannedMs,baseMs,totalMs:Date.now()-started}};
}
