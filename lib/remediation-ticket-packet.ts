import { DashboardError } from "./elastic-dashboard";
import { dashboardCsv } from "./dashboard-csv";
import { worstSeverityOf } from "./vuln-sla";
import { readPatchCoverage } from "./patch-coverage";
import type { PatchGroup } from "./patch-request";
import type { RemediationEvidence } from "./remediation-ticket-model";

export function remediationTicket(company:{id:string;name:string},evidence:RemediationEvidence,observedAt:string):PatchGroup {
  const membership=readPatchCoverage(evidence.coverage),{remediation,hosts}=evidence,cves=evidence.coverage.cves;
  if(hosts.length!==membership.hosts.size || !hosts.length || new Set(hosts.map(h=>JSON.stringify([h.cid,h.hostId]))).size!==hosts.length ||
      hosts.some(h=>!membership.hosts.has(JSON.stringify([h.cid,h.hostId]))) || evidence.findingCount<membership.pairs)
    throw new DashboardError("Remediation evidence is incomplete. Refresh the summary before preparing a draft.",409);
  const tenants=new Set(hosts.map(h=>h.cid));if(tenants.size!==1)throw new DashboardError("Remediation evidence crosses source tenants.",409);
  const tenantId=hosts[0].cid,remediationId=evidence.id.slice(`crowdstrike:${tenantId}:`.length);
  const hostScope=hosts.map(h=>JSON.stringify([h.cid,h.hostId])).sort();
  const maxRisk=hosts.reduce((n,h)=>Math.max(n,h.risk),0),worstSeverity=worstSeverityOf(hosts.map(h=>({severity:h.severity})));
  const cvss=hosts.reduce<number|null>((n,h)=>h.cvss===null?n:Math.max(n??0,h.cvss),null),exprt=[...new Set(hosts.flatMap(h=>h.exprt))].sort();
  const label=`remediation-${remediation.id}`.replace(/[^a-zA-Z0-9_-]/g,"-").slice(0,80);
  const csv=dashboardCsv({columns:["tenant_id","host_id","hostname","local_ip","os","asset_criticality","covered_cve_count","highest_severity","maximum_cvss","exprt_ratings","maximum_gmi_patch_score","known_exploited","maximum_exploit_status","recommended_remediation","source_observed_at"].map(name=>({name,type:"keyword"})),truncated:false,
    rows:hosts.map(h=>[h.cid,h.hostId,h.hostname,h.ip,h.os,h.criticality,h.cveCount,h.severity,h.cvss,h.exprt.join("; "),h.risk,h.kev,h.exploit,remediation.action,observedAt])});
  const ticketBody=["REMEDIATION REQUEST",`Customer: ${company.name} (${company.id})`,"Source: completed CrowdStrike import",`Source observed: ${observedAt}`,
    `Affected devices: ${hosts.length}`,`Open source findings: ${evidence.findingCount}`,`Unique CVEs: ${cves.length}`,
    "","RECOMMENDED ACTION",remediation.title,remediation.action,`Reference: ${remediation.reference || "Not supplied"}`,remediation.link,remediation.vendorUrl,
    "","SOURCE SCORES",`Highest severity: ${worstSeverity ?? "Unknown"}`,`Maximum CVSS: ${cvss ?? "Unknown"}`,`ExPRT ratings: ${exprt.join(", ") || "Unknown"}`,`Highest GMI patch score: ${maxRisk}`,
    "","CVEs COVERED",cves.join(", "),"","AFFECTED ASSETS",`See ${label}-patch-request.csv: one row per device, with that device's CVE count and highest recorded scores. Not every device has every listed CVE.`,
    "","REVIEW AND VERIFY","Confirm ownership and the maintenance window before applying this exact recommended action and target version. Verify closure in the source after patching; creating or closing a ticket does not establish resolution.",
    "Prepared from saved source evidence."].filter(v=>v!==undefined).join("\n");
  const packet:PatchGroup={source:"stored-findings",manualOnly:true,appCompanyId:company.id,companyName:company.name,connectors:["crowdstrike"],
    remediationId:`manual:${remediationId}`,vendorRemediationId:remediation.id,tenantId,title:remediation.title,action:remediation.action,reference:remediation.reference,
    link:remediation.link,vendorUrl:remediation.vendorUrl,published:remediation.published,cves,deviceCount:hosts.length,findingCount:evidence.findingCount,
    hostScope,csv,deviceCves:[],deviceCveCoverage:evidence.coverage,
    reviewRows:hosts.map(h=>({asset:h.hostname || h.hostId,cve:`${h.cveCount} CVEs`,severity:h.severity,risk:h.risk,hostname:h.hostname,ip:h.ip,os:h.os,criticality:h.criticality,connectors:["CrowdStrike"]})),
    worstSeverity,maxRisk,label,ticketTitle:`${remediation.title || "Recommended remediation"} | ${hosts.length} devices`.slice(0,100),ticketBody};
  if(ticketBody.length>200000 || Buffer.byteLength(JSON.stringify(packet))>32*1024*1024)throw new DashboardError("This remediation exceeds the complete ticket export limit. No partial draft was prepared.",413);
  return packet;
}
