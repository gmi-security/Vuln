import {createHash} from 'node:crypto';
// Three-way merge, never a blind replacement of source-derived workflow.
export function applyDefenderWorkflow(candidate,snapshot){
  if(candidate.companyId!==snapshot.companyId)throw Error('Workflow snapshot customer mismatch');
  const decisions=new Map(snapshot.rows.map(row=>[row.finding_id,row]));
  if(decisions.size!==snapshot.rows.length)throw Error('Duplicate workflow finding');
  let conflictCount=0;const conflicts=[],seen=new Set();
  const conflict=(id,field,reason)=>{conflictCount++;if(conflicts.length<100)conflicts.push({findingId:id,field,reason});};
  const records=candidate.records.map(f=>{
    const row=decisions.get(f.id);if(!row)return f;seen.add(f.id);
    if(f.companyId!==candidate.companyId||row.device_id!==f.defender?.deviceId||row.cve!==f.cve){conflict(f.id,'identity','Finding identity changed');return f;}
    const next={...f};
    if(row.patches.assignee){const p=row.patches.assignee;
      if(f.assignee!==p.base&&f.assignee!==p.value)conflict(f.id,'assignee','Assignment changed since the decision');else next.assignee=p.value;}
    if(row.patches.status){const p=row.patches.status;
      if(p.value==='Resolved'&&f.defender.active&&f.defender.runId!==p.sourceRun)conflict(f.id,'status','A newer source import detects this vulnerability');
      else if(!((f.status===p.base&&f.resolvedAt===p.baseResolvedAt)||(f.status===p.value&&f.resolvedAt===p.resolvedAt)))conflict(f.id,'status','Source or saved workflow changed since the decision');
      else{next.status=p.value;next.resolvedAt=p.resolvedAt;}}
    return next;
  });
  for(const id of decisions.keys())if(!seen.has(id))conflict(id,'identity','Decided finding is absent from the candidate');
  if(conflictCount)return {state:'conflict',conflictCount,conflicts};
  return {state:'applied',candidate:{...candidate,records,workflowRevision:snapshot.revision,workflowDecisions:snapshot.rows.length,
    workflowDigest:createHash('sha256').update(JSON.stringify(snapshot)).digest('hex')}};
}
