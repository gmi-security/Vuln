// Freeze the actual scoring inputs in this process. This is not a claim that
// this process has the production worker's in-memory CISA overlay.
import {createHash} from "node:crypto";
import {isKev,isKevRansomware,computeRealRisk,riskPriority} from "./threat";
import type {CompensatingControl,Finding,InventoryAsset} from "./types";
type Asset=Omit<InventoryAsset,"openFindings">;
export function captureDefenderRefreshAssessment(companyId:string,cves:Iterable<string>,inputControls:CompensatingControl[]){
  const controls=structuredClone(inputControls);
  if(controls.some(c=>c.companyId!==companyId||!Number.isFinite(c.effectivenessPct)||c.effectivenessPct<0||c.effectivenessPct>100))throw Error("Invalid assessment controls");
  const threats=[...new Set(cves)].sort().map(cve=>({cve,kev:isKev(cve),ransomware:isKev(cve)&&isKevRansomware(cve)}));
  const evidence={version:1,companyId,origin:"captured-process-threat-state",threats,controls};
  const digest=createHash("sha256").update(JSON.stringify(evidence)).digest("hex"),byCve=new Map(threats.map(row=>[row.cve,row]));
  // Returned evidence is a separate copy so callers cannot mutate the scorer.
  return {digest,evidence:structuredClone(evidence),score(finding:Finding,inventory:Asset|undefined):Partial<Finding>{
    const threat=byCve.get(finding.cve);
    if(finding.companyId!==companyId||inventory?.companyId!==companyId||!threat)throw Error("Assessment scope or threat snapshot missing");
    const {score:raw}=computeRealRisk({cvss:finding.cvss,epss:finding.epss,exploitAvailable:finding.exploitAvailable,
      kev:threat.kev,ransomware:threat.ransomware,exposure:inventory.exposure,criticality:inventory.criticality});
    let control:CompensatingControl|undefined;
    for(const c of controls){if(c.status!=="Active"||(c.cveMatch&&c.cveMatch.toUpperCase()!==finding.cve.toUpperCase())||(c.assetMatch&&!finding.asset.toLowerCase().includes(c.assetMatch.toLowerCase())))continue;
      if(!control||c.effectivenessPct>control.effectivenessPct)control=c;}
    const score=control?Math.max(0,Math.round(raw*(1-control.effectivenessPct/100))):raw;
    return {kev:threat.kev,ransomware:threat.ransomware,assetExposure:inventory.exposure,assetCriticality:inventory.criticality,assetSource:inventory.source,
      realRisk:score,riskPriority:riskPriority(score),compensatingControl:control?{id:control.id,title:control.title,effectivenessPct:control.effectivenessPct,scoreBeforeControl:raw}:null};
  }};
}
