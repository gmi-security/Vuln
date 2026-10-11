// Frozen orchestration from store.ts at 66c3655; comparison only.
// Uses unchanged legacy metrics/compliance/priorities functions as the oracle.
import type {Finding,Severity,Company} from "../../lib/types";
type StoreApi=Pick<typeof import("../../lib/store"),"computeMetrics"|"computePriorities"|"computeAttackSurface"|"computeCompliance"|"findingSlaInfo"|"isRemediationFinding">;
type State={companies:Map<string,Company>;findings:Map<string,Finding>};
import type {SsvcDecision} from "../../lib/ssvc";
import {FRAMEWORKS} from "../../lib/compliance";
const SEVERITIES:Severity[]=["Critical","High","Medium","Low","Info"];
const isOpen=(f:Finding)=>f.status==="Open"||f.status==="In Remediation";
function mttr90Days(findings: Finding[]): number | null {
  const cutoff = Date.now() - 90 * 86_400_000;
  const resolved = findings.filter(
    (f) =>
      f.status === "Resolved" &&
      f.resolvedAt &&
      new Date(f.resolvedAt).getTime() >= cutoff,
  );
  if (resolved.length === 0) return null;
  const meanMs =
    resolved.reduce(
      (sum, f) =>
        sum + (new Date(f.resolvedAt!).getTime() - new Date(f.firstSeen).getTime()),
      0,
    ) / resolved.length;
  return Math.round((meanMs / 86_400_000) * 10) / 10;
}
const SLE_BY_SEVERITY: Record<Severity, number> = {
  Critical: 250_000,
  High: 75_000,
  Medium: 15_000,
  Low: 2_000,
  Info: 0,
};

function annualRate(f: Finding): number {
  let p = 0.05;
  if (f.kev) p = 0.6;
  else if (f.exploitAvailable || f.epss >= 0.3) p = 0.3;
  if (f.assetExposure === "Internet-facing") p += 0.1;
  if (f.assetCriticality === "Crown Jewel") p += 0.1;
  return Math.min(0.9, p);
}

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

export function legacyExecutiveReport(storeApi: StoreApi, s: State, companyId: string): ExecReport | null {
  const company = s.companies.get(companyId);
  if (!company) return null;

  const metrics = storeApi.computeMetrics({ companyId });
  const priorities = storeApi.computePriorities({ companyId, limit: 5000 });
  const surface = storeApi.computeAttackSurface({ companyId });
  const surfaceSummary = surface.summary;

  const open = Array.from(s.findings.values()).filter(
    (f) => f.companyId === companyId && isOpen(f),
  );
  const ale = Math.round(
    open.reduce((sum, f) => sum + SLE_BY_SEVERITY[f.severity] * annualRate(f), 0),
  );

  const slaBySeverity = {} as Record<Severity, { open: number; overdue: number }>;
  for (const sev of SEVERITIES) slaBySeverity[sev] = { open: 0, overdue: 0 };
  for (const f of open.filter(storeApi.isRemediationFinding)) {
    slaBySeverity[f.severity].open += 1;
    if (storeApi.findingSlaInfo(f).overdue) slaBySeverity[f.severity].overdue += 1;
  }
  const companyRemediation = Array.from(s.findings.values()).filter(
    (f) => f.companyId === companyId && storeApi.isRemediationFinding(f),
  );

  const compliance = FRAMEWORKS.map((fw) => {
    const p = storeApi.computeCompliance({ companyId, framework: fw.id }).companies[0];
    return { framework: fw.name, overall: p?.overall ?? "Pass", score: p?.score ?? 100 };
  });

  return {
    generatedAt: "",
    company: { id: company.id, name: company.name, industry: company.industry },
    posture: {
      compositeScore: metrics.composite.score,
      compositeBand: metrics.composite.band,
      exposureScore: metrics.exposureScore,
    },
    findings: {
      open: metrics.totalOpen,
      critical: metrics.severityCounts.Critical,
      high: metrics.severityCounts.High,
      kevOpen: metrics.kevOpen,
    },
    ssvc: {
      act: priorities.summary.act,
      attend: priorities.summary.attend,
      overdue: priorities.summary.overdue,
      kevOverdue: priorities.summary.kevOverdue,
    },
    compliance,
    attackSurface: {
      total: surfaceSummary.total,
      exposedAssets: surfaceSummary.exposedAssets,
      leakedCredentials: surfaceSummary.byCategory["Leaked Credentials"],
      webVulnerabilities: surfaceSummary.byCategory["Web Vulnerabilities"],
    },
    financial: { ale },
    sla: {
      bySeverity: slaBySeverity,
      mttrDays: mttr90Days(companyRemediation),
    },
    topRisks: priorities.items.slice(0, 5).map((i) => ({
      cve: i.cve,
      title: i.title,
      asset: i.asset,
      realRisk: i.realRisk,
      decision: i.decision,
      kev: i.kev,
    })),
  };
}
