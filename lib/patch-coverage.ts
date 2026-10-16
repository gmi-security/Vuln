import { patchRecommendationIds, recommendedRemediationIds, remediationVariantId, type PatchFinding, type Remediation } from "./patch-recommendations";
// Lossless device/CVE membership for large remediation tickets. A bit at index
// n means that host has cves[n]; it never implies a hosts-by-CVEs cross product.
export type PatchCoverage = { cves: string[]; hosts: { cid: string; hostId: string; bits: string }[] };

export function readPatchCoverage(value: PatchCoverage) {
  if (!value || !Array.isArray(value.cves) || !value.cves.length || value.cves.length>100000 ||
      new Set(value.cves).size!==value.cves.length || value.cves.some(c=>!/^CVE-\d{4}-\d{4,19}$/.test(c)) ||
      !Array.isArray(value.hosts) || !value.hosts.length || value.hosts.length>100000)
    throw new Error("Invalid remediation ticket coverage.");
  const cves=new Map(value.cves.map((c,i)=>[c,i])), hosts=new Map<string,Buffer>();
  let pairs=0, bytes=0;
  for(const host of value.hosts) {
    const key=JSON.stringify([host.cid,host.hostId]);
    if(!host.cid || !host.hostId || hosts.has(key) || typeof host.bits!=="string" || host.bits.length>16668)
      throw new Error("Invalid remediation ticket host coverage.");
    const bits=Buffer.from(host.bits,"base64");
    if(bits.toString("base64")!==host.bits || bits.length!==Math.ceil(value.cves.length/8) ||
        (value.cves.length%8 && (bits.at(-1)! >> (value.cves.length%8)))) throw new Error("Invalid remediation ticket coverage bits.");
    let count=0;
    for(const b of bits) {let n=b;while(n){count++;n&=n-1;}}
    if(!count || (bytes+=bits.length)>32*1024*1024 || (pairs+=count)>5000000) throw new Error("Remediation ticket coverage limit exceeded.");
    hosts.set(key,bits);
  }
  return {hosts,pairs,has(cid:string,hostId:string,cve:string) {
    const index=cves.get(cve),bits=hosts.get(JSON.stringify([cid,hostId]));
    return index!==undefined && !!bits && !!(bits[index>>3] & (1<<(index%8)));
  }};
}

// Legacy entries keep their existing whole device/CVE meaning. New compact
// tickets cover one exact action; they must not hide another required fix.
export class TicketedPairs extends Set<string> {
  private coverage: {action:string;data:ReturnType<typeof readPatchCoverage>}[]=[];
  addCoverage(value: PatchCoverage | undefined | null, action?:string) {
    if(value){if(!action)throw new Error("Missing ticket remediation identity.");this.coverage.push({action:action.replace(/^manual:/,""),data:readPatchCoverage(value)});}
  }
  hasAction(cid:string,hostId:string,cve:string,action:string) {
    return this.has(JSON.stringify([cid,hostId,cve])) || this.coverage.some(c=>c.action===action && c.data.has(cid,hostId,cve));
  }
}
export function ticketedAction(pairs:Set<string>,row:PatchFinding,remedy:Remediation) {
  return typeof (pairs as TicketedPairs).hasAction === "function" ? (pairs as TicketedPairs).hasAction(row.cid,row.hostId,row.cve,remediationVariantId(remedy)) : pairs.has(JSON.stringify([row.cid,row.hostId,row.cve]));
}
export function ticketedFinding(pairs:Set<string>,row:PatchFinding) {
  if(pairs.has(JSON.stringify([row.cid,row.hostId,row.cve])))return true;
  if(row.apps.some(app=>!recommendedRemediationIds(app,row.remediations).length))return false;
  const ids=patchRecommendationIds(row);
  return ids.length>0 && ids.every(id=>{const r=row.remediations.find(r=>r.id===id);return !!r && ticketedAction(pairs,row,r);});
}
