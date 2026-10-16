import { normalizePatchFinding, patchRecommendationIds, recommendedRemediationIds } from "./patch-recommendations";
import type { TopFixesResult, TopFix } from "./reporting-top-fixes";

// Runs only in the isolated summary worker, during its existing full-generation
// traversal. Device ordinals come from the scope-checked source accumulator.
export function createSpotlightTopFixes(companyId: string) {
  const groups = new Map<string, TopFix & { devices: Set<number> }>();
  const devices = new Set<number>(), cves = new Set<string>();
  let findingCount=0, missingRemediation=0, pairs=0;
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
    }
  }
  function finish(): TopFixesResult {
    const rows=[...groups.values()].sort((a,b)=>b.deviceCount-a.deviceCount || rank[b.severity]-rank[a.severity] || b.maxRisk-a.maxRisk || b.findingCount-a.findingCount || a.id.localeCompare(b.id))
      .slice(0,50).map(({devices:_,...row})=>row);
    return {companyId,calculatedAt:new Date().toISOString(),totalFixes:groups.size,affectedDevices:devices.size,findingCount,uniqueCves:cves.size,
      missingRemediation,missingDevice:0,limit:50,rows};
  }
  return {add,finish};
}
