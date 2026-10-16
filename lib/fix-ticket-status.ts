import {createHash} from "node:crypto";
import {readPatchCoverage, type PatchCoverage} from "./patch-coverage";
import {remediationVariantId} from "./patch-recommendations";

export type FixTicketStatus = {
  state:"none"|"draft"|"approved"|"sending"|"uncertain"|"failed"|"open"|"partial"|"closed"|"related"|"unavailable";
  tickets:{id:string;kind?:"single"|"group";ticketId:number|null;url?:string;sameFix:boolean;state:string;reviewState:string;closed:boolean}[];
  more:number;moreSingle?:boolean;
  coverage?:{coveredDevices:number;remainingDevices:number;totalDevices:number};
};
export type TicketFixRow = {id:string;source?:string;cve?:string;cves?:string[];deviceCount:number;findingCount:number};
export type FixTicket = {id:string;kind?:"single"|"group";companyId:string;tenantId:string;remediationId:string;vendorRemediationId?:string;
  title:string;action:string;reference:string;link:string;vendorUrl:string;published:string;cves:string[];connectors?:string[];
  state:string;reviewState:string;ticketId:number|null;ticketUrl:string|null;closed:boolean};
export type TicketScope = {id:string;coverage?:PatchCoverage;devices?:{cid:string;hostId:string;cve:string}[]};
export type FixEvidence = {id:string;coverage:PatchCoverage;findingCount:number};
const clean=(value:string)=>value.trim().replace(/\s+/g," ").toLowerCase();
export function ticketMatchesFix(companyId:string,row:TicketFixRow,ticket:FixTicket) {
  if(ticket.companyId!==companyId || ticket.kind==="single")return false;
  if(row.source==="crowdstrike") {
    const base=ticket.remediationId.replace(/^manual:/,"");
    if(row.id===`crowdstrike:${ticket.tenantId}:${base}`)return true;
    if(ticket.vendorRemediationId) {
      const variant=remediationVariantId({...ticket,id:ticket.vendorRemediationId,recommendationType:"recommended"});
      return row.id===`crowdstrike:${ticket.tenantId}:${variant}`;
    }
    // Older Top fixes groups use CVE/vendor ID and can contain different action
    // versions. A shared CVE establishes a related ticket, not complete coverage.
    return false;
  }
  if(ticket.tenantId!==companyId)return false;
  return ticket.cves.some(cve=>createHash("sha256").update(`${companyId}\0${JSON.stringify([cve.toUpperCase(),clean(ticket.action)])}`).digest("hex").slice(0,32)===row.id);
}
function safeUrl(value:string|null) {
  try {const url=new URL(value!);return ["http:","https:"].includes(url.protocol) && !url.username && !url.password ? url.href:undefined;}catch{return undefined;}
}
function coverage(row:TicketFixRow,exact:FixTicket[],scopes:TicketScope[],evidence:FixEvidence|null|undefined,budget:{remaining:number}) {
  if(!evidence || evidence.id!==row.id || evidence.findingCount!==row.findingCount)return;
  try {
    const current=readPatchCoverage(evidence.coverage);
    if(current.hosts.size!==row.deviceCount || evidence.coverage.hosts.some(h=>!row.id.startsWith(`crowdstrike:${h.cid}:`)) ||
      JSON.stringify([...evidence.coverage.cves].sort())!==JSON.stringify([...(row.cves??[])].sort()))return;
    const matches=scopes.filter(scope=>exact.some(ticket=>ticket.id===scope.id));
    if(matches.length!==exact.length)return;
    const lookup=matches.map(scope=>{
      if(scope.coverage)return readPatchCoverage(scope.coverage).has;
      if(!Array.isArray(scope.devices))throw Error("Missing ticket membership");
      const set=new Set(scope.devices.map(d=>JSON.stringify([d.cid,d.hostId,d.cve])));
      return (cid:string,hostId:string,cve:string)=>set.has(JSON.stringify([cid,hostId,cve]));
    });
    let coveredDevices=0;
    for(const host of evidence.coverage.hosts) {
      const bits=current.hosts.get(JSON.stringify([host.cid,host.hostId]))!;let full=true;
      for(let byte=0;byte<bits.length && full;byte++)if(bits[byte])for(let bit=0;bit<8 && full;bit++)if(bits[byte]&(1<<bit)) {
        const cve=evidence.coverage.cves[byte*8+bit];let covered=false;
        for(const has of lookup) {
          if(--budget.remaining<0)return; // One shared request budget; report unverified scope instead of partial math.
          if(has(host.cid,host.hostId,cve)){covered=true;break;}
        }
        if(!covered)full=false;
      }
      if(full)coveredDevices++;
    }
    return {coveredDevices,remainingDevices:row.deviceCount-coveredDevices,totalDevices:row.deviceCount};
  }catch{return;}
}
export function fixTicketStatus(companyId:string,row:TicketFixRow,records:FixTicket[],scopes:TicketScope[]=[],evidence?:FixEvidence|null,budget={remaining:1_000_000}):FixTicketStatus {
  const cves=new Set(row.cves??[row.cve!]);
  const matches=records.filter(t=>t.companyId===companyId && (t.ticketId || t.reviewState!=="dismissed") && t.cves.some(c=>cves.has(c)));
  const exact=matches.filter(t=>ticketMatchesFix(companyId,row,t));
  const open=exact.filter(t=>t.ticketId && !t.closed);
  const detail=open.length ? coverage(row,open,scopes,evidence,budget):undefined;
  let state:FixTicketStatus["state"]="none";
  if(open.length)state=detail && detail.remainingDevices>0 ? "partial":"open";
  else if(exact.some(t=>t.state==="uncertain"))state="uncertain";
  else if(exact.some(t=>t.state==="creating"))state="sending";
  else if(exact.some(t=>t.state==="failed"))state="failed";
  else if(exact.some(t=>t.state==="prepared" && t.reviewState==="approved"))state="approved";
  else if(exact.some(t=>t.state==="prepared"))state="draft";
  else if(exact.some(t=>t.ticketId && t.closed))state="closed";
  else if(matches.length)state="related";
  const order=(t:FixTicket)=>t.ticketId && !t.closed ? 0:t.state==="creating" || t.state==="uncertain" ? 1:t.state==="prepared" ? 2:3;
  const ordered=[...exact.sort((a,b)=>order(a)-order(b)),...matches.filter(t=>!exact.includes(t)).sort((a,b)=>order(a)-order(b))];
  return {state,coverage:detail,more:Math.max(0,ordered.length-5),moreSingle:ordered.slice(5).some(t=>t.kind==="single"),tickets:ordered.slice(0,5).map(t=>({id:t.id,kind:t.kind,ticketId:t.ticketId,url:safeUrl(t.ticketUrl),
    sameFix:exact.includes(t),state:t.state,reviewState:t.reviewState,closed:t.closed}))};
}
