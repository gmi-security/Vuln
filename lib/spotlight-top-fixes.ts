import { normalizePatchFinding, patchRecommendationIds, recommendedRemediationIds, remediationActionKey, remediationVariantId } from "./patch-recommendations";
import type { TopFixesResult, TopFix } from "./reporting-top-fixes";
import { compareRemediationFixes, type RemediationFix } from "./remediation-worklist";

// Runs only in the isolated summary worker, during its existing full-generation
// traversal. Device ordinals come from the scope-checked source accumulator.
export function createSpotlightTopFixes(companyId: string) {
  const groups = new Map<string, TopFix & { devices: Set<number> }>();
  const actions = new Map<string, Omit<RemediationFix,"cves"> & { devices: Set<number>; cves: Set<string> }>();
  const devices = new Set<number>(), cves = new Set<string>();
  let findingCount=0, missingRemediation=0, pairs=0, actionPairs=0, actionCves=0;
  const rank: Record<string,number> = {Critical:4,High:3,Medium:2,Low:1,Info:0,Unknown:-1};
  function add(raw: Record<string,unknown> | undefined, cve: string, device: number) {
    if (!raw || !/^CVE-\d{4}-\d{4,19}$/.test(cve)) { missingRemediation++; return; }
    const row=normalizePatchFinding(raw,cve), ids=patchRecommendationIds(row);
    // As with patch preparation, incomplete app recommendations require source
    // refresh/investigation. Never guess that the minimum patch is recommended.
    if (!ids.length || row.apps.some(app=>!recommendedRemediationIds(app,row.remediations).length) ||
      ids.some(id=>!row.remediations.some(remedy=>remedy.id===id && remedy.action.trim()))) { missingRemediation++; return; }
    findingCount++; devices.add(device); cves.add(cve);
    const severity=Object.keys(rank).find(s=>s.toUpperCase()===row.severity.toUpperCase()) ?? "Unknown";
    for (const id of ids) {
      const key=JSON.stringify([row.cid,cve,id]), remedy=row.remediations.find(r=>r.id===id)!;
      let group=groups.get(key);
      if (!group) {
        if (groups.size>=100_000) throw new Error("Top fixes group limit exceeded.");
        group={id:`crowdstrike:${cve}:${id}`,cve,remediation:remedy.action.slice(0,2000),deviceCount:0,findingCount:0,maxRisk:0,severity,devices:new Set()};
        groups.set(key,group);
      }
      if (!group.devices.has(device)) {
        if (++pairs>5_000_000) throw new Error("Top fixes device/action limit exceeded.");
        group.devices.add(device); group.deviceCount++;
      }
      group.findingCount++;group.maxRisk=Math.max(group.maxRisk,row.risk);
      if(rank[severity]>rank[group.severity])group.severity=severity;
      const actionKey=JSON.stringify([row.cid,remediationActionKey(remedy)]);
      let action=actions.get(actionKey);
      if(!action) {
        if(actions.size>=100_000)throw new Error("Remediation worklist group limit exceeded.");
        action={id:`crowdstrike:${row.cid}:${remediationVariantId(remedy)}`,remediation:remedy.action.slice(0,2000),
          reference:remedy.reference.slice(0,500),grouping:"vendor-remediation",severity,deviceCount:0,findingCount:0,maxRisk:0,devices:new Set(),cves:new Set()};
        actions.set(actionKey,action);
      }
      if(!action.devices.has(device)) {
        if(++actionPairs>5_000_000)throw new Error("Remediation worklist device/action limit exceeded.");
        action.devices.add(device);action.deviceCount++;
      }
      if(!action.cves.has(cve)) {
        if(++actionCves>5_000_000)throw new Error("Remediation worklist CVE/action limit exceeded.");
        action.cves.add(cve);
      }
      action.findingCount++;action.maxRisk=Math.max(action.maxRisk,row.risk);
      if(rank[severity]>rank[action.severity])action.severity=severity;
    }
  }
  function finish(): TopFixesResult {
    const rows=[...groups.values()].sort((a,b)=>b.deviceCount-a.deviceCount || rank[b.severity]-rank[a.severity] || b.maxRisk-a.maxRisk || b.findingCount-a.findingCount || a.id.localeCompare(b.id))
      .slice(0,50).map(({devices:_,...row})=>row);
    return {companyId,calculatedAt:new Date().toISOString(),totalFixes:groups.size,affectedDevices:devices.size,findingCount,uniqueCves:cves.size,
      missingRemediation,missingDevice:0,limit:50,rows,
      remediationWorklist:{totalGroups:actions.size,limit:50,rows:[...actions.values()]
        .sort(compareRemediationFixes)
        .slice(0,50).map(({devices:_,cves,...action})=>({...action,cves:[...cves].sort()}))}};
  }
  return {add,finish};
}
