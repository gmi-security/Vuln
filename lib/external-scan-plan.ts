import { scannerExactTargetKey } from "./scanner-target-scope";

// Read-only preview of ONE Nessus scan definition -> precisely its OWN
// proposed Greenbone target set. These are configured targets, not proof
// that a particular completed Nessus run reached or assessed each host.
// No launch/admission functions are called from this module.
export type ExternalScheduleEntry = {
  nessusScanId: number;
  scanName: string;
  enabled: boolean;
  nextOccurrence: string | null;
  offsetNextTrigger: string | null;
};
export type ExternalScheduleMatrix = {
  generatedAt: string;
  companies: Array<{ companyId: string; companyName: string; scans: ExternalScheduleEntry[] }>;
};
export type ExternalApprovedRoute = {
  companyId: string;
  provider: string;
  targets: string[];
  sourceScope?: string;
};
// Sourced ONLY from a bounded GET /editor/scan/<id>, after a global Nessus
// roster confirms actual folder ownership against reviewed routing.
export type ExternalNessusDefinition = {
  companyId: string;
  nessusScanId: number;
  folderId: number;
  targets: string[];
  source: "nessus-editor";
};
export type ExternalScanCandidate = {
  companyId: string;
  companyName: string;
  target: string;
  nessusScanId: number;
  nessusScanName: string;
  nominalOffsetAt: string;
  state: "review-required";
};
export type ExternalScanPlan = {
  mode: "preview-only";
  generatedAt: string;
  launchesEnabled: false;
  routeStatus: "unavailable" | "reviewed";
  candidates: ExternalScanCandidate[];
  blocked: Array<{ companyId: string; reason: string; nessusScanId?: number }>;
};

function canonicalScope(values: readonly string[] | undefined): Map<string,string> | null {
  if (!Array.isArray(values) || values.length < 1 || values.length > 4096)
    return null;
  const m=new Map<string,string>();
  try {
    for(const item of values){
      const key=scannerExactTargetKey(item);
      if(m.has(key))return null;
      m.set(key,item);
    }
  }catch{return null;}
  return m;
}
const k=(company:string,scanId:number)=>JSON.stringify([company,scanId]);

/**
 * The old planner used all reviewed Vulners targets for a company and
 * assigned them to the earliest Nessus schedule, multiplying unrelated
 * scans. This version requires BOTH independently reviewed provider
 * routes AND an exact trusted Nessus definition for EACH scan ID.
 * There is no historical findings/asset inventory fallback.
 *
 * Equal configured lists are PREVIEW equality, not assessed coverage.
 * Future dispatch still requires pinned Nessus run proof for each host,
 * approved customer window, globally bounded remote worker and durable
 * per-target task claims. This function never enables or launches scans.
 */
export function buildExternalScanPlan(
  matrix: ExternalScheduleMatrix,
  vulnersRoutes: readonly ExternalApprovedRoute[] | null,
  nessusRoutes: readonly ExternalApprovedRoute[] | null = null,
  definitions: readonly ExternalNessusDefinition[] | null = null,
): ExternalScanPlan {
  const out: ExternalScanPlan={
    mode:"preview-only",generatedAt:matrix.generatedAt,launchesEnabled:false,
    routeStatus:vulnersRoutes===null||nessusRoutes===null?"unavailable":"reviewed",
    candidates:[],blocked:[],
  };
  if(vulnersRoutes===null||nessusRoutes===null||definitions===null) {
    out.blocked.push({companyId:"*",reason:
      "Both approved scanner routes and read-only per-definition Nessus targets are required. No company-wide fallback."});
    return out;
  }
  const now=Date.parse(matrix.generatedAt);
  if(!Number.isFinite(now)||!Array.isArray(matrix.companies)||matrix.companies.length>100){
    out.blocked.push({companyId:"*",reason:"Schedule matrix invalid or oversized."});
    return out;
  }
  const defs=new Map<string,ExternalNessusDefinition[]>();
  if(definitions.length>100){
    out.blocked.push({companyId:"*",reason:"Nessus definition inventory is oversized."});
    return out;
  }
  for(const d of definitions){
    if(!Number.isSafeInteger(d.nessusScanId)||d.nessusScanId<1 ||
       !Number.isSafeInteger(d.folderId)||d.folderId<1 ||
       d.source!=="nessus-editor"||!d.companyId){
      out.blocked.push({companyId:"*",reason:"Unverified Nessus definition identity."});
      return out;
    }
    const key=k(d.companyId,d.nessusScanId);
    defs.set(key,[...(defs.get(key)??[]),d]);
  }
  // Cross-company overlap is an explicit hold, not permission for either
  // tenant's Greenbone scan. Compare both approved route types.
  const owners=new Map<string,string>(), contested=new Set<string>();
  for(const route of [...vulnersRoutes,...nessusRoutes]){
    for(const item of route.targets??[]){
      try{
        const key=scannerExactTargetKey(item);
        const prior=owners.get(key);
        if(prior && prior!==route.companyId)contested.add(key);
        else owners.set(key,route.companyId);
      }catch{/* Later scope parsing fails closed. */}
    }
  }
  const scansSeen=new Set<string>();
  for(const company of matrix.companies){
    const vMatches=vulnersRoutes.filter(r=>r.companyId===company.companyId&&r.provider==="vulners");
    const nMatches=nessusRoutes.filter(r=>r.companyId===company.companyId&&r.provider==="nessus");
    if(vMatches.length!==1||nMatches.length!==1){
      out.blocked.push({companyId:company.companyId,
        reason:"Exactly one reviewed route per scanner is required."});
      continue;
    }
    const folderId=Number(nMatches[0].sourceScope);
    const V=canonicalScope(vMatches[0].targets),N=canonicalScope(nMatches[0].targets);
    if(!Number.isSafeInteger(folderId)||folderId<1||!V||!N){
      out.blocked.push({companyId:company.companyId,
        reason:"Malformed approved Nessus folder or scanner scope."});
      continue;
    }
    if(!Array.isArray(company.scans)||company.scans.length>100){
      out.blocked.push({companyId:company.companyId,
        reason:"Unverifiable Nessus schedule list."});
      continue;
    }
    for(const scan of company.scans){
      if(!scan.enabled)continue;
      const id=scan.nessusScanId;
      if(!Number.isSafeInteger(id)||id<1||
         !scan.nextOccurrence||!scan.offsetNextTrigger||
         !Number.isFinite(Date.parse(scan.nextOccurrence))||
         !Number.isFinite(Date.parse(scan.offsetNextTrigger))||
         Date.parse(scan.offsetNextTrigger)<=now||
         Math.abs(Date.parse(scan.offsetNextTrigger)-
           Date.parse(scan.nextOccurrence)-3_600_000)>1000){
        out.blocked.push({companyId:company.companyId,
          reason:"Invalid enabled Nessus recurrence or +60m offset.",nessusScanId:id});
        continue;
      }
      const scanKey=k(company.companyId,id);
      if(scansSeen.has(scanKey)){
        out.blocked.push({companyId:company.companyId,
          reason:"Duplicate Nessus definition in schedule matrix.",nessusScanId:id});
        continue;
      }
      scansSeen.add(scanKey);
      const match=defs.get(scanKey)??[];
      if(match.length!==1||match[0].folderId!==folderId){
        out.blocked.push({companyId:company.companyId,
          reason:"Missing or wrong-folder live Nessus definition targets.",nessusScanId:id});
        continue;
      }
      const T=canonicalScope(match[0].targets);
      if(!T){
        out.blocked.push({companyId:company.companyId,
          reason:"Nessus definition has invalid or duplicate expanded targets.",nessusScanId:id});
        continue;
      }
      // Fail closed for the ENTIRE scan if even ONE configured host lacks
      // dual approval. A partial approved intersection is not target parity.
      if([...T.keys()].some(key=>!N.has(key)||!V.has(key)||contested.has(key))){
        out.blocked.push({companyId:company.companyId,
          reason:"Not every exact Nessus definition target is independently approved for both scanners.",
          nessusScanId:id});
        continue;
      }
      // Use only this definition, never a company-wide union or a
      // single earliest Nessus recurrence for all hosts.
      for(const target of T.values())out.candidates.push({
        companyId:company.companyId,companyName:company.companyName,
        target,nessusScanId:id,nessusScanName:scan.scanName,
        nominalOffsetAt:scan.offsetNextTrigger,state:"review-required",
      });
    }
  }
  out.candidates.sort((a,b)=>a.nominalOffsetAt.localeCompare(b.nominalOffsetAt)||
    a.companyId.localeCompare(b.companyId)||
    a.nessusScanId-b.nessusScanId||a.target.localeCompare(b.target));
  return out;
}
