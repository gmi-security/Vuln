import {readPatchCoverage, type PatchCoverage} from './patch-coverage';

export type ProgressTicket = {id:string;kind:'single'|'group';companyId:string;ticketId:number;hostCount:number;
  createdAt:string;scopeHash:string;packet:Record<string,unknown>;ticketUrl?:string;ticketStatus?:string;closed?:boolean};
export type ProgressPair = {key:string;deviceKey:string;source:string;hostId:string;cid?:string;cve:string;findingId?:string;hostname?:string};
export type ProgressScope = {ticket:ProgressTicket;pairs:ProgressPair[];error?:string};
export type DefenderProgressProof = {deviceId:string;revision:number;observedAt:string};
export type ProgressEvidence = {complete:boolean;scopeMatches:boolean;assessmentAt:string|null;generation:string;
  present:boolean;covered:boolean;suppressed?:boolean;reason?:string;absenceIsFix?:boolean;retained?:boolean;defenderProof?:DefenderProgressProof};
export type ProgressObservation = ProgressPair & {state:'detected'|'clear'|'unknown';reason:string;assessmentAt:string|null;generation:string|null;reappeared?:boolean;retained?:boolean;defenderProof?:DefenderProgressProof};
export type ProgressSummary = {devices:number;detected:number;clear:number;unknown:number;reappeared:number;pairs:number};
const validCve=(v:unknown):v is string=>typeof v==='string'&&/^CVE-\d{4}-\d{4,19}$/.test(v);
const text=(v:unknown)=>typeof v==='string'?v:'';
export const MAX_PROGRESS_PAIRS=100_000;

/** Decode saved membership, never a host/CVE Cartesian product for group tickets. */
export function progressScope(ticket:ProgressTicket):ProgressScope {
  const result:ProgressScope={ticket,pairs:[]},p=ticket.packet,seen=new Set<string>();
  const fail=(error:string)=>({...result,pairs:[],error});
  if(p.appCompanyId!==ticket.companyId)return fail('Original customer scope is unavailable.');
  if(!Number.isFinite(Date.parse(ticket.createdAt)))return fail('Ticket creation time is unavailable.');
  const add=(source:string,hostId:string,cve:string,cid?:string,findingId?:string,hostname?:string)=>{
    if(!hostId||!validCve(cve))throw Error('Original device/CVE membership is incomplete.');
    if(source==='crowdstrike')cid=cid?.toLowerCase();
    const deviceKey=JSON.stringify([cid||ticket.companyId,hostId]);
    const key=JSON.stringify([source,cid||ticket.companyId,hostId,cve,findingId||'']);
    if(seen.has(key))return;seen.add(key);
    if(seen.size>MAX_PROGRESS_PAIRS)throw Error('Original scope exceeds the supported comparison size; operator review is needed.');
    result.pairs.push({key,deviceKey,source,hostId,cve,cid,findingId,hostname});
  };
  try {
    const sources=Array.isArray(p.connectors)?p.connectors.map(v=>text(v).toLowerCase()).filter(Boolean):[];
    const cs=ticket.kind==='single'||sources.length===1&&sources[0]==='crowdstrike'||p.source!=='stored-findings';
    if(cs){
      const hosts=new Set(Array.isArray(p.hostScope)?p.hostScope as string[]:[]);
      if(!hosts.size)throw Error('Original device scope is unavailable.');
      if(ticket.kind==='single'){
        for(const h of hosts){const pair=JSON.parse(h);if(!Array.isArray(pair)||pair.length!==2||!pair.every(v=>typeof v==='string'&&v))throw Error('Invalid host scope.');add('crowdstrike',pair[1],text(p.cve),pair[0]);}
      }else if(p.deviceCveCoverage){
        const coverage=p.deviceCveCoverage as PatchCoverage,data=readPatchCoverage(coverage);
        if(data.hosts.size!==hosts.size||[...data.hosts.keys()].some(k=>!hosts.has(k)))throw Error('Original device/CVE membership is incomplete.');
        for(const host of coverage.hosts){
          const bits=data.hosts.get(JSON.stringify([host.cid,host.hostId]))!;
          for(let byte=0;byte<bits.length;byte++)if(bits[byte])for(let bit=0;bit<8;bit++)if(bits[byte]&(1<<bit))add('crowdstrike',host.hostId,coverage.cves[byte*8+bit],host.cid);
        }
      }else if(Array.isArray(p.deviceCves)){
        for(const row of p.deviceCves){if(!hosts.has(JSON.stringify([row.cid,row.hostId])))throw Error('Invalid host membership.');add('crowdstrike',row.hostId,row.cve,row.cid);}
      }
    }else if(Array.isArray(p.reviewRows)){
      for(const row of p.reviewRows){
        const required=Array.isArray(row.connectors)&&row.connectors.length?row.connectors:sources;
        for(const source of required.length?required:['unknown'])add(text(source).toLowerCase(),text(row.asset),text(row.cve),undefined,text(row.findingId)||undefined,text(row.hostname)||undefined);
      }
    }
    if(!result.pairs.length||new Set(result.pairs.map(r=>r.deviceKey)).size!==ticket.hostCount)throw Error('Complete original device/CVE scope is unavailable.');
  }catch(error){return fail(error instanceof Error?error.message:'Original scope is unavailable.');}
  return result;
}

export function assessProgress(pair:ProgressPair,baseline:string,evidence:ProgressEvidence|null):ProgressObservation {
  const row:ProgressObservation={...pair,state:'unknown',reason:'No qualifying completed assessment is available.',assessmentAt:evidence?.assessmentAt??null,generation:evidence?.generation??null,
    ...(evidence?.defenderProof?{defenderProof:evidence.defenderProof}:{}),...(evidence?.retained?{retained:true}:{})};
  if(!evidence)return row;
  if(!evidence.complete||!evidence.scopeMatches)return {...row,reason:evidence.reason||'Source scope or publication is not verified.'};
  if(!evidence.assessmentAt||!Number.isFinite(Date.parse(baseline))||!(Date.parse(evidence.assessmentAt)>Date.parse(baseline)))return {...row,reason:evidence.reason||'Waiting for fresh device data after ticket creation.'};
  if(evidence.present)return {...row,state:'detected',reason:'Still detected by the source after ticket creation.'};
  if(evidence.suppressed)return {...row,reason:'Suppressed or excluded evidence cannot verify remediation.'};
  if(evidence.covered||pair.source==='crowdstrike'&&evidence.absenceIsFix)return {...row,state:'clear',reason:evidence.absenceIsFix?'Fixed: no longer reported by the next completed CrowdStrike import.':evidence.retained?'Earlier verified absence retained at the original evidence date; no new device assessment is claimed.':'No longer detected in a later completed assessment covering this device.'};
  return {...row,reason:evidence.reason||'Device coverage is not verified; absence alone is not proof.'};
}
export function markReappearances(rows:ProgressObservation[],previouslyClear:ReadonlySet<string>){
  for(const row of rows)if(row.state==='detected'&&previouslyClear.has(row.key))row.reappeared=true;
}
export function summarizeProgress(rows:ProgressObservation[]):ProgressSummary {
  const devices=new Map<string,{state:ProgressObservation['state'];reappeared:boolean}>();
  const rank={clear:0,unknown:1,detected:2};
  for(const row of rows){const prior=devices.get(row.deviceKey);devices.set(row.deviceKey,{state:prior&&rank[prior.state]>rank[row.state]?prior.state:row.state,reappeared:!!prior?.reappeared||!!row.reappeared});}
  const values=[...devices.values()];return {devices:values.length,detected:values.filter(r=>r.state==='detected').length,clear:values.filter(r=>r.state==='clear').length,unknown:values.filter(r=>r.state==='unknown').length,reappeared:values.filter(r=>r.reappeared).length,pairs:rows.length};
}
