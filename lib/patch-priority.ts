import type {FixTicketStatus} from "./fix-ticket-status";
export type PriorityThreat = {kev:boolean|null;active:boolean|null;epss:number|null;updatedAt:string|null};
export type PriorityInput = {
  severity:string;cvss:number|null;cvssSource:string;kev:boolean|null;active:boolean|null;publicExploit:boolean|null;epss:number|null;
  exposed:boolean|null;critical:boolean|null;products:string[];remediation:string;owner?:string|null;dueAt?:string|null;
  observedAt?:string|null;threatAt?:string|null;
};
export type PriorityRow = {
  id:string;cves:string[];source:"platform"|"crowdstrike";sources:string[];remediation:string;products:string[];
  deviceCount:number;deviceCountIsLowerBound:boolean;findingCount:number;severity:string;cvss:number|null;cvssSources:string[];
  kev:boolean|null;active:boolean|null;publicExploit:boolean|null;epss:number|null;exposedDevices:number|null;criticalDevices:number|null;
  urgency:1|2|3|4;reasons:string[];gaps:string[];owners:string[];unassignedFindings:number;dueAt:string|null;
  lastObserved:string|null;threatObserved:string|null;missingRemediation:number;ticketStatus?:FixTicketStatus;
};
export type PriorityWorklist = {version:1;byCve:PriorityRow[];byRemediation:PriorityRow[];totalCves:number;totalRemediations:number;notices:string[]};
export const priorityLabels={1:"Urgent",2:"High",3:"Review",4:"Routine"} as const;
const ranks:Record<string,number>={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0,NONE:0,UNKNOWN:-1};
const date=(value:string|null|undefined)=>value&&Number.isFinite(Date.parse(value))?new Date(value).toISOString():null;
const minDate=(a:string|null,b:string|null)=>a&&b?(a<b?a:b):a??b;
const maxDate=(a:string|null,b:string|null)=>a&&b?(a>b?a:b):a??b;
const tri=(a:boolean|null,b:boolean|null)=>a===true||b===true?true:a===false&&b===false?false:null;
const finite=(n:number|null,min:number,max:number)=>typeof n==="number"&&Number.isFinite(n)&&n>=min&&n<=max?n:null;
function append(values:string[],next:string[],limit=8){for(const value of next)if(value&&!values.includes(value)&&values.length<limit)values.push(value.slice(0,300));}

// Explicit review policy, not a claimed implementation of SSVC or a vendor score.
export function priorityDecision(input:PriorityInput):{urgency:PriorityRow["urgency"];reasons:string[];gaps:string[]} {
  const severity=input.severity.toUpperCase(),cvss=finite(input.cvss,0,10),epss=finite(input.epss,0,1),gaps:string[]=[];
  if(input.exposed===null)gaps.push("Exposure unknown");if(input.critical===null)gaps.push("Asset criticality unknown");
  if(input.kev===null||input.active===null||input.publicExploit===null)gaps.push("Threat evidence incomplete");
  if(epss===null)gaps.push("EPSS unknown");if(cvss===null)gaps.push("CVSS unknown");if(!input.remediation.trim())gaps.push("Remediation missing");
  const reasons:string[]=[];
  if(input.kev===true)reasons.push("CISA KEV recorded");if(input.active===true)reasons.push("Observed exploitation recorded");
  if(reasons.length){if(input.exposed===true)reasons.push("Internet-facing device");if(input.critical===true)reasons.push("Business-critical device");return {urgency:1,reasons,gaps};}
  if(severity==="CRITICAL"||severity==="HIGH"||(cvss!==null&&cvss>=7))reasons.push(`${severity==="UNKNOWN"?"High":severity.toLowerCase()} technical severity`);
  if(input.publicExploit===true)reasons.push("Public exploit recorded");if(epss!==null&&epss>=0.1)reasons.push("EPSS at least 10%");
  if(input.exposed===true)reasons.push("Internet-facing device");if(input.critical===true)reasons.push("Business-critical device");
  if(reasons.length)return {urgency:2,reasons,gaps};
  if(gaps.length)return {urgency:3,reasons:["Complete missing evidence before scheduling"],gaps};
  return {urgency:4,reasons:["No elevated signal in the recorded evidence"],gaps};
}
export function comparePriority(a:PriorityRow,b:PriorityRow){return a.urgency-b.urgency||b.deviceCount-a.deviceCount||
  (a.dueAt??"9999").localeCompare(b.dueAt??"9999")||(ranks[b.severity.toUpperCase()]??-1)-(ranks[a.severity.toUpperCase()]??-1)||a.id.localeCompare(b.id);}
type Device=string|number;
type Group={row:PriorityRow;devices:Set<Device>;cves:Set<string>};
export function createPriorityWorklist(source:PriorityRow["source"]) {
  const cves=new Map<string,Group>(),fixes=new Map<string,Group>(),context=new Map<Device,{exposed:boolean|null;critical:boolean|null}>();
  function add(map:Map<string,Group>,id:string,cve:string,device:Device|undefined,input:PriorityInput,sharedDevices?:Set<Device>){
    const decision=priorityDecision(input);
    if(device===undefined){decision.gaps.push("Device identity missing");if(decision.urgency===4){decision.urgency=3;decision.reasons=["Complete missing evidence before scheduling"];}}
    let group=map.get(id);
    if(!group){if(map.size>=100000)throw Error("Priority summary group capacity exceeded");group={devices:sharedDevices??new Set(),cves:new Set(),row:{
      id,cves:[],source,sources:[source],remediation:input.remediation.slice(0,2000),products:[],deviceCount:0,deviceCountIsLowerBound:false,findingCount:0,severity:"Unknown",cvss:null,cvssSources:[],
      kev:input.kev,active:input.active,publicExploit:input.publicExploit,epss:null,exposedDevices:null,criticalDevices:null,...decision,owners:[],unassignedFindings:0,dueAt:null,lastObserved:null,threatObserved:null,missingRemediation:0}};map.set(id,group);}
    const row=group.row;group.cves.add(cve);if(device!==undefined)group.devices.add(device);else row.deviceCountIsLowerBound=true;row.findingCount++;
    if((ranks[input.severity.toUpperCase()]??-1)>(ranks[row.severity.toUpperCase()]??-1))row.severity=input.severity;
    const cvss=finite(input.cvss,0,10),epss=finite(input.epss,0,1);if(cvss!==null)row.cvss=Math.max(row.cvss??0,cvss);if(epss!==null)row.epss=Math.max(row.epss??0,epss);
    row.kev=tri(row.kev,input.kev);row.active=tri(row.active,input.active);row.publicExploit=tri(row.publicExploit,input.publicExploit);
    if(decision.urgency<row.urgency){row.urgency=decision.urgency;row.reasons=decision.reasons;}else if(decision.urgency===row.urgency)append(row.reasons,decision.reasons,4);
    append(row.gaps,decision.gaps);append(row.products,input.products);if(cvss!==null)append(row.cvssSources,[input.cvssSource]);
    if(input.owner)append(row.owners,[input.owner]);else row.unassignedFindings++;
    row.dueAt=minDate(row.dueAt,date(input.dueAt));row.lastObserved=maxDate(row.lastObserved,date(input.observedAt));row.threatObserved=maxDate(row.threatObserved,date(input.threatAt));
    if(!input.remediation.trim())row.missingRemediation++;
    if(device!==undefined){const previous=context.get(device);context.set(device,{exposed:previous?tri(previous.exposed,input.exposed):input.exposed,critical:previous?tri(previous.critical,input.critical):input.critical});}
  }
  function display(group:Group):PriorityRow {
    let exposed=0,critical=0,unknownExposure=false,unknownCritical=false;
    for(const device of group.devices){const value=context.get(device);if(value?.exposed===true)exposed++;else if(value?.exposed!==false)unknownExposure=true;
      if(value?.critical===true)critical++;else if(value?.critical!==false)unknownCritical=true;}
    return {...group.row,cves:[...group.cves].sort(),deviceCount:group.devices.size,
      exposedDevices:unknownExposure||group.row.deviceCountIsLowerBound?null:exposed,criticalDevices:unknownCritical||group.row.deviceCountIsLowerBound?null:critical};
  }
  return {addCve(cve:string,device:Device|undefined,input:PriorityInput,devices?:Set<Device>){add(cves,`cve:${cve}`,cve,device,input,devices);},
    addFix(id:string,cve:string,device:Device|undefined,input:PriorityInput,devices?:Set<Device>){add(fixes,id,cve,device,input,devices);},
    finish():PriorityWorklist {return {version:1,byCve:[...cves.values()].map(display).sort(comparePriority),byRemediation:[...fixes.values()].map(display).sort(comparePriority).slice(0,50),totalCves:cves.size,totalRemediations:fixes.size,notices:[]};}};
}

// Across independent source inventories a summed count is not a unique estate count.
export function combinePriorityWorklists(lists:PriorityWorklist[],notices:string[]=[]):PriorityWorklist {
  const cves=new Map<string,PriorityRow>();
  for(const list of lists)for(const row of list.byCve){const prior=cves.get(row.cves[0]);if(!prior){cves.set(row.cves[0],{...row});continue;}
    const first=comparePriority(prior,row)<=0?prior:row;
    cves.set(row.cves[0],{...first,id:`cve:${row.cves[0]}`,sources:[...new Set([...prior.sources,...row.sources])],
      deviceCount:Math.max(prior.deviceCount,row.deviceCount),deviceCountIsLowerBound:true,findingCount:prior.findingCount+row.findingCount,
      severity:(ranks[prior.severity.toUpperCase()]??-1)>=(ranks[row.severity.toUpperCase()]??-1)?prior.severity:row.severity,
      cvss:prior.cvss===null?row.cvss:row.cvss===null?prior.cvss:Math.max(prior.cvss,row.cvss),cvssSources:[...new Set([...prior.cvssSources,...row.cvssSources])],
      kev:tri(prior.kev,row.kev),active:tri(prior.active,row.active),publicExploit:tri(prior.publicExploit,row.publicExploit),
      epss:prior.epss===null?row.epss:row.epss===null?prior.epss:Math.max(prior.epss,row.epss),exposedDevices:null,criticalDevices:null,
      products:[...new Set([...prior.products,...row.products])].slice(0,8),owners:[...new Set([...prior.owners,...row.owners])].slice(0,8),
      unassignedFindings:prior.unassignedFindings+row.unassignedFindings,missingRemediation:prior.missingRemediation+row.missingRemediation,
      dueAt:minDate(prior.dueAt,row.dueAt),lastObserved:maxDate(prior.lastObserved,row.lastObserved),threatObserved:maxDate(prior.threatObserved,row.threatObserved),
      gaps:[...new Set([...prior.gaps,...row.gaps,"Cross-source device overlap unverified"])]});
  }
  return {version:1,byCve:[...cves.values()].sort(comparePriority).slice(0,50),byRemediation:lists.flatMap(l=>l.byRemediation).sort(comparePriority).slice(0,50),totalCves:cves.size,totalRemediations:lists.reduce((n,l)=>n+l.totalRemediations,0),notices:[...new Set([...notices,...lists.flatMap(l=>l.notices)])]};
}

export function validSavedPriority(value:PriorityWorklist):boolean {
  const count=(n:unknown):n is number=>typeof n==="number"&&Number.isSafeInteger(n)&&n>=0;
  const strings=(v:unknown,max:number)=>Array.isArray(v)&&v.length<=max&&v.every(s=>typeof s==="string"&&s.length<=2000);
  const flag=(v:unknown)=>v===null||typeof v==="boolean";
  const timestamp=(v:unknown)=>v===null||typeof v==="string"&&Number.isFinite(Date.parse(v));
  if(value.version!==1||!count(value.totalCves)||value.totalCves>100000||!count(value.totalRemediations)||value.totalRemediations>100000||
    !Array.isArray(value.byCve)||value.byCve.length!==value.totalCves||!Array.isArray(value.byRemediation)||
    value.byRemediation.length!==Math.min(50,value.totalRemediations)||!strings(value.notices,10))return false;
  return [value.byCve,value.byRemediation].every((rows,index)=>new Set(rows.map(r=>r?.id)).size===rows.length&&rows.every(r=>r&&
    r.source==="crowdstrike"&&Array.isArray(r.sources)&&r.sources.length===1&&r.sources[0]==="crowdstrike"&&
    typeof r.id==="string"&&r.id.length<=250&&Array.isArray(r.cves)&&r.cves.length>0&&r.cves.length<=100000&&
    r.cves.every(c=>typeof c==="string"&&/^CVE-\d{4}-\d{4,19}$/.test(c))&&new Set(r.cves).size===r.cves.length&&
    (index===0?r.cves.length===1&&r.id===`cve:${r.cves[0]}`:r.id.startsWith("crowdstrike:"))&&
    typeof r.remediation==="string"&&r.remediation.length<=2000&&typeof r.severity==="string"&&r.severity.length<30&&
    count(r.deviceCount)&&count(r.findingCount)&&r.deviceCount<=r.findingCount&&typeof r.deviceCountIsLowerBound==="boolean"&&
    [r.kev,r.active,r.publicExploit].every(flag)&&[r.lastObserved,r.threatObserved,r.dueAt].every(timestamp)&&
    (r.cvss===null||finite(r.cvss,0,10)!==null)&&(r.epss===null||finite(r.epss,0,1)!==null)&&
    [r.exposedDevices,r.criticalDevices].every(n=>n===null||count(n)&&n<=r.deviceCount)&&[1,2,3,4].includes(r.urgency)&&
    [r.reasons,r.gaps,r.products,r.owners,r.cvssSources].every(a=>strings(a,8))&&
    count(r.unassignedFindings)&&r.unassignedFindings<=r.findingCount&&count(r.missingRemediation)&&r.missingRemediation<=r.findingCount));
}
