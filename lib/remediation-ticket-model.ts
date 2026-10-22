import type { PatchCoverage } from "./patch-coverage";
import type { PatchFinding, Remediation } from "./patch-recommendations";

type Host = { cid:string; hostId:string; hostname:string; ip:string; os:string; criticality:string;
  severity:string; cvss:number|null; risk:number; exprt:string[]; kev:boolean|null; exploit:number|null; cveCount:number };
export type RemediationEvidence = { id:string; remediation:Remediation; hosts:Host[]; coverage:PatchCoverage; findingCount:number };
const ranks:Record<string,number>={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,NONE:1,UNKNOWN:0};

// Built once during the existing summary traversal, not during a ticket click.
// Sparse 256-CVE bit blocks avoid retaining millions of finding objects or IDs.
export function createRemediationEvidence() {
  type Acc = {remediation:Remediation;cves:Map<string,number>;hosts:Map<string,Host & {blocks:Map<number,Buffer>}>;findings:number};
  const actions=new Map<string,Acc>();let blocks=0,hosts=0,pairs=0,metadataBytes=0;
  let unavailableReason:string|undefined;
  function capacity(){actions.clear();unavailableReason="Ticket evidence exceeds the bounded summary capacity. Prepare smaller CVE requests from this worklist; the complete worklist counts remain available.";}
  function add(id:string,remediation:Remediation,row:PatchFinding) {
    if(unavailableReason)return;
    let action=actions.get(id);
    if(!action){if(actions.size>=100000)return capacity();action={remediation,cves:new Map(),hosts:new Map(),findings:0};actions.set(id,action);}
    if(!action.cves.has(row.cve))action.cves.set(row.cve,action.cves.size);
    if(action.cves.size>100000)return capacity();
    const index=action.cves.get(row.cve)!, key=JSON.stringify([row.cid,row.hostId]);
    let host=action.hosts.get(key);
    if(!host){
      if(++hosts>100000)return capacity();
      host={cid:row.cid,hostId:row.hostId,hostname:row.hostname,ip:row.ip,os:row.os,criticality:row.hostCriticality,
        severity:row.severity,cvss:row.cvss,risk:row.risk,exprt:[],kev:row.kev,exploit:row.exploit,cveCount:0,blocks:new Map()};
      if((metadataBytes+=Buffer.byteLength(JSON.stringify(host)))>16*1024*1024)return capacity();
      action.hosts.set(key,host);
    }
    const block=index>>8;let bits=host.blocks.get(block);
    if(!bits){if(++blocks>1000000)return capacity();bits=Buffer.alloc(32);host.blocks.set(block,bits);}
    const byte=(index%256)>>3,mask=1<<(index%8);
    if(!(bits[byte]&mask)){if(++pairs>5000000)return capacity();bits[byte]|=mask;host.cveCount++;}
    if((ranks[row.severity.toUpperCase()]??0)>(ranks[host.severity.toUpperCase()]??0))host.severity=row.severity;
    if(row.cvss!==null)host.cvss=Math.max(host.cvss??0,row.cvss);
    host.risk=Math.max(host.risk,row.risk);host.kev=host.kev===true || row.kev===true ? true : host.kev===false && row.kev===false ? false : null;
    if(row.exploit!==null)host.exploit=Math.max(host.exploit??0,row.exploit);
    for(const [field,value] of [["hostname",row.hostname],["ip",row.ip],["os",row.os],["criticality",row.hostCriticality]] as const)if(!host[field] && value)host[field]=value;
    if(row.exprt && !host.exprt.includes(row.exprt))host.exprt.push(row.exprt);
    action.findings++;
  }
  function finish(ids:string[],optionalIds:string[]=[]) {
    const result:Record<string,RemediationEvidence>={};let bytes=0;
    if(unavailableReason)return result;
    const required=new Set(ids);
    for(const id of new Set([...ids,...optionalIds])) {
      const action=actions.get(id);if(!action)throw new Error("Missing remediation evidence.");
      const cves=[...action.cves.keys()].sort(), newIndices=new Map(cves.map((c,i)=>[c,i]));
      // Bound the dense serialized form BEFORE allocating host buffers. Sparse
      // evidence can otherwise expand dramatically when hosts have disjoint CVEs.
      const denseBytes=action.hosts.size*(4*Math.ceil(Math.ceil(cves.length/8)/3)+200);
      if(bytes+denseBytes>32*1024*1024){if(!required.has(id))continue;capacity();return {};}
      const remap=[...action.cves.keys()].map(c=>newIndices.get(c)!);
      const coverage:PatchCoverage={cves,hosts:[]}, hostRows:Host[]=[];
      for(const {blocks,...host} of action.hosts.values()) {
        const bits=Buffer.alloc(Math.ceil(cves.length/8));
        for(const [block,chunk] of blocks)for(let byte=0;byte<chunk.length;byte++)if(chunk[byte])for(let bit=0;bit<8;bit++) {
          if(chunk[byte]&(1<<bit)){const i=remap[block*256+byte*8+bit];bits[i>>3]|=1<<(i%8);}
        }
        coverage.hosts.push({cid:host.cid,hostId:host.hostId,bits:bits.toString("base64")});hostRows.push(host);
      }
      const evidence={id,remediation:action.remediation,hosts:hostRows,coverage,findingCount:action.findings};
      const size=Buffer.byteLength(JSON.stringify(evidence));
      if(bytes+size>32*1024*1024){if(!required.has(id))continue;capacity();return {};}
      bytes+=size;
      result[id]=evidence;
    }
    return result;
  }
  return {add,finish,get unavailableReason(){return unavailableReason;}};
}

