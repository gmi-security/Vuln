import { createHash } from "node:crypto";
import { setImmediate } from "node:timers/promises";
import type { Finding,SlaSettings } from "./types";
import {createPriorityWorklist,type PriorityWorklist,type PriorityThreat} from "./patch-priority";
import {platformPriorityInput} from "./patch-priority-input";
import { reportingFindingClass } from "./reporting-metrics";
import type { RemediationWorklist } from "./remediation-worklist";
import type { FixTicketStatus } from "./fix-ticket-status";

export type TopFix = {
  id: string; cve: string; remediation: string; deviceCount: number;
  findingCount: number; maxRisk: number; severity: string; source?: "platform" | "crowdstrike";
  ticketStatus?: FixTicketStatus;
};
export type TopFixesResult = {
  companyId: string; calculatedAt: string; totalFixes: number; affectedDevices: number;
  findingCount: number; uniqueCves: number; missingRemediation: number; missingDevice: number;
  limit: number; rows: TopFix[]; sources?: string[]; notices?: string[];
  remediationWorklist?: RemediationWorklist;
  priorityWorklist?: PriorityWorklist;
};
const LIMIT = 50;
const severityRank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const clean = (value: string) => value.trim().replace(/\s+/g, " ");

// Read current platform evidence, not ticket workflow state. Like manual
// consolidation, unstructured remediation text is grouped within ONE CVE:
// matching prose across CVEs does not prove that one patch covers both.
// Iterate once without copying/sorting the full findings collection or
// constructing host CSVs. Only the highest-impact summaries leave this module.
export async function buildTopFixes(companyId: string, findings: Iterable<Finding>, include?: (finding: Finding) => boolean, threats?:Map<string,PriorityThreat>,sla?:SlaSettings): Promise<TopFixesResult> {
  const priority=threats?createPriorityWorklist("platform"):undefined;
  const groups = new Map<string, { id:string;cve: string; remediation: string; devices: Set<string>; findingCount: number; maxRisk: number; severity: string }>();
  const devices = new Set<string>(), cves = new Set<string>();
  let findingCount = 0, missingRemediation = 0, missingDevice = 0, visited = 0;
  for (const finding of findings) {
    if (++visited % 5000 === 0) await setImmediate();
    if (finding.companyId !== companyId || (finding.status !== "Open" && finding.status !== "In Remediation")) continue;
    if (reportingFindingClass(finding.connector) === "osint" || !/^CVE-\d{4}-\d{4,19}$/i.test(finding.cve)) continue;
    if (include && !include(finding)) continue;
    const input=priority?platformPriorityInput(finding,threats?.get(finding.cve.toUpperCase()),sla):undefined;
    if(input)priority!.addCve(finding.cve.toUpperCase(),finding.asset?.trim()||undefined,input);
    const remediation = clean(finding.remediation || "");
    if (!remediation) { missingRemediation++; continue; }
    const cve = finding.cve.toUpperCase(), key = JSON.stringify([cve, remediation.toLowerCase()]);
    let group = groups.get(key);
    if (!group) {
      group = { id:createHash("sha256").update(`${companyId}\0${key}`).digest("hex").slice(0,32),cve, remediation, devices: new Set(), findingCount: 0, maxRisk: 0, severity: "Unknown" };
      groups.set(key, group);
    }
    group.findingCount++; findingCount++; cves.add(cve);
    const asset = finding.asset?.trim();
    if (asset) { group.devices.add(asset); devices.add(asset); } else missingDevice++;
    if (Number.isFinite(finding.realRisk)) group.maxRisk = Math.max(group.maxRisk, finding.realRisk);
    if ((severityRank[finding.severity] ?? -1) > (severityRank[group.severity] ?? -1)) group.severity = finding.severity;
    if(input)priority!.addFix(group.id,cve,asset||undefined,input,group.devices);
  }
  const compare = ([keyA,a]: [string,Group], [keyB,b]: [string,Group]) => b.devices.size - a.devices.size ||
    (severityRank[b.severity] ?? -1) - (severityRank[a.severity] ?? -1) || b.maxRisk - a.maxRisk || b.findingCount - a.findingCount || keyA.localeCompare(keyB);
  type Group = (typeof groups extends Map<string,infer V> ? V : never);
  // Keep only the best 50; do not sort/copy every group on the event loop.
  const top: [string,Group][] = [];
  const severityTop: [string,Group][] = [];
  const bySeverity = (a: [string,Group], b: [string,Group]) =>
    (severityRank[b[1].severity] ?? -1)-(severityRank[a[1].severity] ?? -1) || compare(a,b);
  function retain(list: [string,Group][], entry: [string,Group], order: typeof compare) {
    if (list.length === LIMIT && order(entry,list[list.length-1]) >= 0) return;
    let low=0,high=list.length;
    while (low<high) { const mid=(low+high)>>>1; if (order(entry,list[mid])<0) high=mid; else low=mid+1; }
    list.splice(low,0,entry); if (list.length>LIMIT) list.pop();
  }
  for (const entry of groups) {
    if (++visited % 5000 === 0) await setImmediate();
    retain(top,entry,compare); retain(severityTop,entry,bySeverity);
  }
  const display = ([key,group]: [string,Group]) => ({
      id: createHash("sha256").update(`${companyId}\0${key}`).digest("hex").slice(0,32),
      cve: group.cve, remediation: group.remediation.slice(0,2000), deviceCount: group.devices.size,
      findingCount: group.findingCount, maxRisk: group.maxRisk, severity: group.severity,
    });
  const rows = top.map(display);
  return { companyId, calculatedAt: new Date().toISOString(), totalFixes: groups.size, affectedDevices: devices.size,
    findingCount, uniqueCves: cves.size, missingRemediation, missingDevice, limit: LIMIT, rows,priorityWorklist:priority?.finish(),
    remediationWorklist:{totalGroups:groups.size,limit:LIMIT,rows:severityTop.map(entry=>{
      const {cve,...fix}=display(entry); return {...fix,cves:[cve],grouping:"single-cve" as const};
    })} };
}

// Bounded cache of summaries only. Imports/status edits increment the store
// revision. Map replacement covers hydration; TTL bounds legacy mutations.
// Host sets and full packet data are never retained in this cache.
const cache = new Map<string, { findings: WeakRef<ReadonlyMap<string,Finding>>; revision: number; expires: number; result: TopFixesResult }>();
let computing: { key: string; findings: ReadonlyMap<string,Finding>; revision: number; promise: Promise<TopFixesResult> } | undefined;
export async function cachedTopFixes(companyId: string, findings: ReadonlyMap<string,Finding>, revision: number, policyKey="platform", include?: (finding: Finding) => boolean,threats?:Map<string,PriorityThreat>,sla?:SlaSettings): Promise<TopFixesResult> {
  const key=JSON.stringify([companyId,policyKey]), previous = cache.get(key);
  if (previous && previous.findings.deref() === findings && previous.revision === revision && previous.expires > Date.now()) return previous.result;
  if (computing) {
    if (computing.key === key && computing.findings === findings && computing.revision === revision) return computing.promise;
    // Avoid several customers allocating large aggregation sets concurrently.
    await computing.promise;
    return cachedTopFixes(companyId,findings,revision,policyKey,include,threats,sla);
  }
  const promise = buildTopFixes(companyId,findings.values(),include,threats,sla);
  computing = { key,findings,revision,promise };
  try {
    const result = await promise;
    cache.delete(key);
    if (cache.size >= 16) cache.delete(cache.keys().next().value!);
    cache.set(key, { findings: new WeakRef(findings), revision, expires: Date.now() + 60_000, result });
    return result;
  } finally { computing = undefined; }
}
