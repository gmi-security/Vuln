import type {Company,Finding,InventoryAsset,Scan,Severity,SlaSettings} from "./types";
import {ssvc,dueInfo,type SsvcDecision} from "./ssvc";
import {FRAMEWORKS,evaluateFramework,type ComplianceSignals} from "./compliance";
import {slaDaysFor} from "./vuln-sla";

export type ExecReport = {
  generatedAt: string;
  company: { id: string; name: string; industry: string };
  posture: { compositeScore: number; compositeBand: string; exposureScore: number };
  findings: { open: number; critical: number; high: number; kevOpen: number };
  ssvc: { act: number; attend: number; overdue: number; kevOverdue: number };
  compliance: { framework: string; overall: string; score: number }[];
  attackSurface: {
    total: number;
    exposedAssets: number;
    leakedCredentials: number;
    webVulnerabilities: number;
  };
  financial: { ale: number };
  // Remediation SLA rollup: open + overdue counts per severity against the
  // configured settings.sla days, plus 90-day mean time to remediate.
  sla: {
    bySeverity: Record<Severity, { open: number; overdue: number }>;
    mttrDays: number | null;
  };
  topRisks: {
    cve: string;
    title: string;
    asset: string;
    realRisk: number;
    decision: SsvcDecision;
    kev: boolean;
  }[];
};

const DAY = 86_400_000;
const severities: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const weights: Record<Severity, number> = {Critical:40, High:20, Medium:8, Low:2, Info:0};
const losses: Record<Severity, number> = {Critical:250_000, High:75_000, Medium:15_000, Low:2_000, Info:0};
const decisions: Record<SsvcDecision, number> = {Act:0, Attend:1, "Track*":2, Track:3};
type Owner = Pick<Company, "id" | "name" | "industry">;
type ScanInput = Pick<Scan, "companyId" | "completedAt">;
type AssetInput = Pick<InventoryAsset, "companyId" | "identifier" | "hostname" | "ipAddresses">;
export type ExecutiveContext = {
  // One explicit observation time and policy for the whole calculation. A future
  // saved reader must also pin policy/KEV revisions and time-based expiry.
  now: number;
  sla: SlaSettings;
  isComplianceKev: (cve: string) => boolean;
};
type Ranked = ExecReport["topRisks"][number] & {overdue:boolean; daysLeft:number};
const compare = (a: Ranked, b: Ranked) => decisions[a.decision]-decisions[b.decision] ||
  Number(b.overdue)-Number(a.overdue) || b.realRisk-a.realRisk || a.daysLeft-b.daysLeft;

// Preserve the existing executive categorization without constructing all of
// Attack Surface's sorted item lists, which the executive report never renders.
function surfaceClass(f: Finding): "credentials" | "web" | "other" {
  const raw=(f.category.split(":").pop()||"").trim().toLowerCase(),cve=f.cve.toLowerCase();
  const has=(...keys:string[])=>keys.some(k=>raw.includes(k)||cve.includes(k));
  if(has("leaksite","compromise","password","hash","bruter","account_external","breach"))return "credentials";
  if(has("nuclei","sql_injection","lfi","wp_scanner","wordpress","joomla","drupal","api_scanner","directory_index","admin_panel","vulnerability"))return "web";
  return "other";
}

/** Pure calculation: no store, timers, provider requests or writes. Memory is
 * five ranked rows plus distinct finding/exposure asset identifiers. Call assets
 * after findings so inventory coverage can be counted without retaining assets.
 */
export function createExecutiveReportAccumulator(company: Owner, context: ExecutiveContext) {
  if(!Number.isFinite(context.now))throw new Error("Executive report observation time required");
  const now=context.now,sla={...context.sla},isComplianceKev=context.isComplianceKev;
  const owner={id:company.id,name:company.name,industry:company.industry};
  const findingAssets=new Set<string>(),surfaceAssets=new Set<string>(),top:Ranked[]=[];
  const severity=Object.fromEntries(severities.map(s=>[s,{open:0,overdue:0}])) as ExecReport["sla"]["bySeverity"];
  const counts={open:0,critical:0,high:0,kevOpen:0};
  const priority={act:0,attend:0,overdue:0,kevOverdue:0};
  const surface={total:0,leakedCredentials:0,webVulnerabilities:0};
  let exposure=0,financial=0,slaScoped=0,compositeBreaches=0,known=0,scanned=0,resolved=0,remediationMs=0;
  let latestScanAge:number|null=null,assetsStarted=false,finished=false;
  const signals:ComplianceSignals={openTotal:0,criticalOpen:0,highCritOpen:0,externalFailing:0,slaBreaches30:0,
    slaBreachesMed90:0,kevOpen:0,lastScanDaysAgo:null,scanOverdue30:true,scanOverdue90:true};
  const active=()=>{if(finished)throw new Error("Executive report already finished");};
  function finding(f:Finding) {
    active();if(assetsStarted)throw new Error("Executive findings must precede inventory");
    if(f.companyId!==owner.id)return;
    const open=f.status==="Open"||f.status==="In Remediation",osint=f.connector==="spiderfoot"||f.connector==="artemis";
    // Preserve existing ALE scope, which includes open OSINT. Changing that
    // policy belongs in a separate reviewed change, not a storage refactor.
    if(open){
      let rate=f.kev?0.6:f.exploitAvailable||f.epss>=0.3?0.3:0.05;
      if(f.assetExposure==="Internet-facing")rate+=0.1;if(f.assetCriticality==="Crown Jewel")rate+=0.1;
      financial+=losses[f.severity]*Math.min(0.9,rate);
    }
    if(osint){
      // Legacy surface includes accepted/false-positive exposures, excluding
      // only Resolved. Overview has different scope; do not silently unify it.
      if(f.status!=="Resolved"){
        surface.total++;surfaceAssets.add(f.asset);const kind=surfaceClass(f);
        if(kind==="credentials")surface.leakedCredentials++;if(kind==="web")surface.webVulnerabilities++;
      }
      return;
    }
    findingAssets.add(f.asset.trim().toLowerCase());
    const first=Date.parse(f.firstSeen);
    if(f.status==="Resolved"&&f.resolvedAt&&Date.parse(f.resolvedAt)>=now-90*DAY){resolved++;remediationMs+=Date.parse(f.resolvedAt)-first;}
    if(!open)return;
    counts.open++;if(f.severity==="Critical")counts.critical++;if(f.severity==="High")counts.high++;if(f.kev)counts.kevOpen++;
    exposure+=weights[f.severity]*(f.exploitAvailable?1.5:1)*(1+f.epss);
    severity[f.severity].open++;
    if(f.severity!=="Info"){
      const due=first+sla[f.severity]*DAY;
      if(Number.isFinite(due)&&due<now)severity[f.severity].overdue++;
      slaScoped++;if((now-first)/DAY>slaDaysFor(f.severity,sla))compositeBreaches++;
    }
    const decision=ssvc(f),due=dueInfo(f,decision.slaDays,now);
    if(decision.decision==="Act")priority.act++;if(decision.decision==="Attend")priority.attend++;
    if(due.overdue){priority.overdue++;if(f.kev)priority.kevOverdue++;}
    const row:Ranked={cve:f.cve,title:f.title,asset:f.asset,realRisk:f.realRisk,decision:decision.decision,kev:f.kev,...due};
    if(top.length<5||compare(row,top[top.length-1])<0){top.push(row);top.sort(compare);if(top.length>5)top.pop();}
    signals.openTotal++;if(f.severity==="Critical")signals.criticalOpen++;
    if(f.severity==="Critical"||f.severity==="High"){signals.highCritOpen++;if((now-first)/DAY>30)signals.slaBreaches30++;}
    if(f.severity==="Medium"&&(now-first)/DAY>90)signals.slaBreachesMed90++;
    if(f.assetExposure==="Internet-facing"&&(f.cvssV3||f.cvssV2||f.cvss||0)>=4)signals.externalFailing++;
    // Compliance historically consults the current catalog while other
    // executive sections use the saved finding KEV flag. Preserve both inputs.
    if(isComplianceKev(f.cve))signals.kevOpen++;
  }
  function scan(s:ScanInput){
    active();if(s.companyId!==owner.id||!s.completedAt)return;
    const age=(now-Date.parse(s.completedAt))/DAY;latestScanAge=latestScanAge===null?age:Math.min(latestScanAge,age);
  }
  function asset(a:AssetInput){
    active();assetsStarted=true;if(a.companyId!==owner.id)return;known++;
    if([a.identifier,a.hostname,...a.ipAddresses].some(k=>findingAssets.has(k.trim().toLowerCase())))scanned++;
  }
  function finish():ExecReport {
    active();finished=true;
    const exposureScore=Math.round(100*(1-Math.exp(-exposure/900)));
    const values={exposure:exposureScore,kevPressure:counts.open?Math.round(counts.kevOpen/counts.open*100):0,
      slaBreach:slaScoped?Math.round(compositeBreaches/slaScoped*100):0,coverageGap:known?Math.round((1-scanned/known)*100):0};
    const components:[keyof typeof values,number][]=[["exposure",0.4],["kevPressure",0.25],["slaBreach",0.2],...(known?[["coverageGap",0.15] as [keyof typeof values,number]]:[])];
    const total=components.reduce((sum,[,weight])=>sum+weight,0);
    const score=Math.round(components.reduce((sum,[key,weight])=>sum+values[key]*(weight/total),0));
    signals.lastScanDaysAgo=latestScanAge===null?null:Math.floor(latestScanAge);
    signals.scanOverdue30=signals.lastScanDaysAgo===null||signals.lastScanDaysAgo>30;
    signals.scanOverdue90=signals.lastScanDaysAgo===null||signals.lastScanDaysAgo>90;
    const compliance=FRAMEWORKS.map(fw=>{const evaluated=evaluateFramework(signals,fw.id);return {framework:fw.name,overall:evaluated.overall,score:evaluated.score};});
    return {generatedAt:"",company:owner,posture:{compositeScore:score,
      compositeBand:score>=80?"Critical":score>=60?"High":score>=40?"Elevated":score>=20?"Guarded":"Low",exposureScore},
      findings:counts,ssvc:priority,compliance,attackSurface:{...surface,exposedAssets:surfaceAssets.size},financial:{ale:Math.round(financial)},
      sla:{bySeverity:severity,mttrDays:resolved?Math.round(remediationMs/resolved/DAY*10)/10:null},
      topRisks:top.map(({cve,title,asset,realRisk,decision,kev})=>({cve,title,asset,realRisk,decision,kev}))};
  }
  return {finding,scan,asset,finish};
}

export function buildExecutiveReport(company:Owner,findings:Iterable<Finding>,scans:Iterable<ScanInput>,assets:Iterable<AssetInput>,context:ExecutiveContext):ExecReport {
  const report=createExecutiveReportAccumulator(company,context);
  for(const row of findings)report.finding(row);for(const row of scans)report.scan(row);for(const row of assets)report.asset(row);
  return report.finish();
}
