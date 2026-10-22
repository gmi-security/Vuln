import type {Finding,SlaSettings} from "./types";
import type {PatchFinding} from "./patch-recommendations";
import type {PriorityInput,PriorityThreat} from "./patch-priority";
const positive=(a:boolean|null|undefined,b:boolean|null|undefined):boolean|null=>a===true||b===true?true:typeof a==="boolean"?a:typeof b==="boolean"?b:null;
export function platformPriorityInput(f:Finding,threat?:PriorityThreat,sla?:SlaSettings):PriorityInput {
  const verified=!!f.assetSource&&f.assetSource!=="inferred";
  const first=Date.parse(f.firstSeen),days=sla?.[f.severity as keyof SlaSettings];
  return {severity:f.severity,cvss:f.defender?.cvss??(Number.isFinite(f.cvss)&&f.cvss>0?f.cvss:null),
    cvssSource:`${f.connector}${f.cvssV3>0?" CVSS v3":" CVSS (version unknown)"}`,
    kev:positive(threat?.kev,f.kev),active:threat?.active??null,publicExploit:typeof f.exploitAvailable==="boolean"?f.exploitAvailable:null,
    epss:threat?.epss??(f.epss>0&&f.epss<=1?f.epss:null),exposed:verified&&f.assetExposure?f.assetExposure==="Internet-facing":null,
    critical:verified&&f.assetCriticality?["Crown Jewel","High"].includes(f.assetCriticality):null,
    products:[],remediation:f.remediation||"",owner:f.assignee,
    dueAt:f.dueAt??(Number.isFinite(first)&&typeof days==="number"?new Date(first+days*86400000).toISOString():null),
    observedAt:f.lastSeen,threatAt:threat?.updatedAt??null};
}
export function spotlightPriorityInput(f:PatchFinding,remediation:string,threat?:PriorityThreat):PriorityInput {
  const exposure=f.exposure.trim().toLowerCase(),criticality=f.hostCriticality.trim().toLowerCase();
  return {severity:f.severity,cvss:f.cvss,cvssSource:"CrowdStrike CVSS (version unknown)",kev:positive(threat?.kev,f.kev),
    active:positive(threat?.active,f.exploit!==null?f.exploit>=90:null),publicExploit:f.exploit!==null?f.exploit>=30:null,epss:threat?.epss??null,
    exposed:["internet-facing","external","public","yes"].includes(exposure)?true:["internal","isolated","no"].includes(exposure)?false:null,
    critical:["critical","high","crown jewel"].includes(criticality)?true:["normal","low","medium"].includes(criticality)?false:null,
    products:[...new Set(f.apps.map(a=>[a.vendor,a.product].filter(Boolean).join(" ")).filter(Boolean))],remediation,observedAt:f.updated,threatAt:threat?.updatedAt??null};
}
