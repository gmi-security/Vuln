// Offline candidate contract. No store hydration, persistence, source client or
// publication call. The operator supplies one pinned baseline and scoring context.
import {planDefenderProjection,type DefenderSnapshot} from "./defender-projection";
import type {Finding,InventoryAsset} from "./types";

type Asset=Omit<InventoryAsset,"openFindings">;
export type DefenderRefreshInput={
  company:{id:string;name:string;isDemo?:boolean};
  baseline:{runId:string|null;savedAt:string;findings:Finding[];assets:Asset[]};
  source:{revision:number;snapshot:DefenderSnapshot};
  assessmentContext:string;
};
const requireValue=(value:unknown,message:string)=>{if(!value)throw new Error(message);};
const validDate=(value:string)=>typeof value==="string"&&Number.isFinite(Date.parse(value));
function unique<T>(rows:T[],key:(row:T)=>string,message:string){const keys=new Set<string>();for(const row of rows){const k=key(row);requireValue(k&&!keys.has(k),message);keys.add(k);}}

export function prepareDefenderRefreshCandidate(input:DefenderRefreshInput,
  score:Parameters<typeof planDefenderProjection>[4]){
  const {company,baseline,source,assessmentContext}=input,{snapshot}=source;
  requireValue(/^CO-[A-Za-z0-9-]+$/.test(company.id)&&company.name&&!company.isDemo&&snapshot.companyId===company.id,"Explicit non-demo customer required");
  requireValue(Number.isSafeInteger(source.revision)&&source.revision>0&&snapshot.runId&&validDate(snapshot.observedAt)&&validDate(baseline.savedAt),"Complete source and baseline metadata required");
  requireValue(typeof assessmentContext==="string"&&assessmentContext.trim()&&assessmentContext.length<=200,"Pinned assessment context required");
  requireValue(baseline.findings.length<=500000&&snapshot.findings.length<=500000&&baseline.assets.length<=100000&&snapshot.devices.length<=100000,"Offline candidate record limit exceeded");
  requireValue(baseline.findings.every(f=>f.companyId===company.id)&&baseline.assets.every(a=>a.companyId===company.id),"Baseline contains another customer");
  unique(baseline.findings,f=>f.id,"Duplicate baseline finding ID");unique(baseline.assets,a=>a.id,"Duplicate baseline asset ID");
  unique(baseline.findings.filter(f=>f.defender),f=>JSON.stringify([f.defender!.deviceId,f.cve]),"Duplicate baseline device/CVE");
  unique(baseline.assets.filter(a=>a.defenderDeviceId),a=>a.defenderDeviceId!,"Duplicate baseline Defender device identity");
  unique(snapshot.devices,d=>d.deviceId,"Duplicate source device");
  unique(snapshot.findings,f=>JSON.stringify([f.deviceId,f.cve]),"Duplicate source device/CVE");
  requireValue(snapshot.findings.every(f=>f.deviceId&&/^CVE-\d{4}-\d{4,19}$/i.test(f.cve)),"Invalid source device/CVE");
  const sameRun=baseline.runId===snapshot.runId;
  // A retry of an already-applied import must not reopen a finding that an
  // analyst resolved afterwards or rescore it using a different threat cache.
  if(!sameRun){
    requireValue(baseline.findings.every(f=>!f.defender||Date.parse(f.defender.observedAt)<=Date.parse(snapshot.observedAt)),"Source observation precedes baseline evidence");
  }
  const findings=new Map(baseline.findings.map(f=>[f.id,f])),assets=new Map(baseline.assets.map(a=>[a.id,a]));
  let changedFindings=0,changedAssets=0;
  if(!sameRun){
    const changes=planDefenderProjection(snapshot,company.name,baseline.findings,baseline.assets,score);
    for(const [id,f] of changes.findings)findings.set(id,f);
    for(const [id,a] of changes.assets)assets.set(id,a);
    changedFindings=changes.findings.size;changedAssets=changes.assets.size;
  }
  // Other scanner records participate in correlation but remain owned by their
  // existing store. Only records with explicit Defender evidence enter this model.
  const records=[...findings.values()].filter(f=>f.defender);
  requireValue(records.length<=500000,"Offline candidate record limit exceeded");
  return {companyId:company.id,sourceRun:snapshot.runId,observedAt:snapshot.observedAt,
    baselineSavedAt:baseline.savedAt,baselineRun:baseline.runId,sourceRevision:source.revision,
    assessmentContext,sameRun,changedFindings,changedAssets,records,assets:[...assets.values()]};
}
