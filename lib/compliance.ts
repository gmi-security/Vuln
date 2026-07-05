import type { ComplianceRequirement, ComplianceStatus } from "@/lib/types";

// Multi-framework compliance engine.
//
// Every supported framework is evaluated against the SAME set of signals derived
// from the vulnerability data (below), so adding a framework is just declaring
// its controls and how each maps onto those signals. This keeps PCI DSS, NIST,
// CMMC, HIPAA, and FedRAMP consistent and audit-defensible.

export type ComplianceSignals = {
  openTotal: number;
  criticalOpen: number;
  highCritOpen: number;
  externalFailing: number; // internet-facing findings at CVSS >= 4.0
  slaBreaches30: number; // high/critical open past 30 days
  slaBreachesMed90: number; // medium open past 90 days
  kevOpen: number; // open findings on CISA KEV (actively exploited)
  lastScanDaysAgo: number | null;
  scanOverdue30: boolean; // no completed scan in 30 days (monthly cadence)
  scanOverdue90: boolean; // no completed scan in 90 days (quarterly cadence)
};

type Eval = { status: ComplianceStatus; detail: string; failing: number };
type ControlDef = {
  id: string;
  title: string;
  evaluate: (s: ComplianceSignals) => Eval;
};
export type FrameworkDef = {
  id: string;
  name: string;
  short: string;
  controls: ControlDef[];
};

const P = (detail: string): Eval => ({ status: "Pass", detail, failing: 0 });
const F = (failing: number, detail: string): Eval => ({ status: "Fail", detail, failing });
const AR = (detail: string): Eval => ({ status: "At Risk", detail, failing: 0 });

const scanCadence = (s: ComplianceSignals, overdue: boolean, cadence: string): Eval =>
  s.lastScanDaysAgo === null
    ? F(1, "No completed scan on record.")
    : overdue
      ? AR(`Last completed scan ${s.lastScanDaysAgo}d ago — ${cadence} cadence at risk.`)
      : P(`Last completed scan ${s.lastScanDaysAgo}d ago — within ${cadence} cadence.`);

const remediation = (s: ComplianceSignals): Eval =>
  s.highCritOpen > 0 || s.slaBreaches30 > 0
    ? F(
        s.highCritOpen || s.slaBreaches30,
        `${s.highCritOpen} high/critical open` +
          (s.slaBreaches30 ? ` · ${s.slaBreaches30} past the 30-day remediation window` : "") +
          ".",
      )
    : P("No unresolved high/critical findings past remediation timelines.");

const kevControl = (s: ComplianceSignals): Eval =>
  s.kevOpen > 0
    ? F(s.kevOpen, `${s.kevOpen} open finding(s) on the CISA KEV catalog (actively exploited).`)
    : P("No open findings on the CISA Known Exploited Vulnerabilities catalog.");

export const FRAMEWORKS: FrameworkDef[] = [
  {
    id: "pci",
    name: "PCI DSS 4.0",
    short: "PCI DSS",
    controls: [
      {
        id: "6.3.1",
        title: "Vulnerabilities identified and risk-ranked",
        evaluate: () =>
          P("All findings risk-ranked via composite real-risk (CVSS × exploitation × environment)."),
      },
      {
        id: "6.3.3",
        title: "Critical/high-risk patches applied within one month",
        evaluate: (s) =>
          s.slaBreaches30 > 0
            ? F(s.slaBreaches30, `${s.slaBreaches30} critical/high finding(s) past the 30-day patch window.`)
            : P("No critical/high findings past the 30-day patch window."),
      },
      {
        id: "11.3.1",
        title: "Internal scans quarterly; high/critical resolved & rescanned",
        evaluate: (s) =>
          s.highCritOpen > 0
            ? F(s.highCritOpen, `${s.highCritOpen} high/critical finding(s) unresolved.`)
            : scanCadence(s, s.scanOverdue90, "quarterly"),
      },
      {
        id: "11.3.2",
        title: "External ASV scan passing (no CVSS ≥ 4.0 on internet-facing)",
        evaluate: (s) =>
          s.externalFailing > 0
            ? F(s.externalFailing, `${s.externalFailing} internet-facing finding(s) at CVSS ≥ 4.0 — ASV failure.`)
            : P("No internet-facing findings at or above CVSS 4.0 — ASV pass."),
      },
    ],
  },
  {
    id: "nist-800-53",
    name: "NIST SP 800-53 Rev 5",
    short: "NIST 800-53",
    controls: [
      { id: "RA-3", title: "Risk Assessment", evaluate: () => P("Findings risk-ranked and prioritized by real-risk.") },
      { id: "RA-5", title: "Vulnerability Monitoring & Scanning", evaluate: (s) => scanCadence(s, s.scanOverdue90, "quarterly") },
      { id: "RA-5(2)", title: "Update vulnerabilities to be scanned (KEV)", evaluate: kevControl },
      { id: "SI-2", title: "Flaw Remediation", evaluate: remediation },
      {
        id: "CA-7",
        title: "Continuous Monitoring",
        evaluate: (s) => (s.scanOverdue30 ? AR("No completed scan in 30 days — continuous monitoring cadence at risk.") : P("Monitoring cadence within 30 days.")),
      },
    ],
  },
  {
    id: "nist-800-171",
    name: "NIST SP 800-171 Rev 2",
    short: "NIST 800-171",
    controls: [
      { id: "3.11.1", title: "Periodically assess risk to operations", evaluate: () => P("Risk assessed continuously via real-risk scoring of findings.") },
      { id: "3.11.2", title: "Scan for vulnerabilities periodically", evaluate: (s) => scanCadence(s, s.scanOverdue90, "quarterly") },
      { id: "3.11.3", title: "Remediate vulnerabilities per risk assessments", evaluate: remediation },
      {
        id: "3.14.1",
        title: "Identify, report, and correct flaws timely",
        evaluate: (s) =>
          s.slaBreaches30 > 0
            ? F(s.slaBreaches30, `${s.slaBreaches30} high/critical flaw(s) not corrected within 30 days.`)
            : P("Flaws corrected within remediation timelines."),
      },
    ],
  },
  {
    id: "cmmc",
    name: "CMMC 2.0 Level 2",
    short: "CMMC L2",
    controls: [
      { id: "RA.L2-3.11.2", title: "Scan for vulnerabilities", evaluate: (s) => scanCadence(s, s.scanOverdue90, "quarterly") },
      { id: "RA.L2-3.11.3", title: "Remediate vulnerabilities", evaluate: remediation },
      { id: "SI.L1-3.14.1", title: "Identify & correct flaws timely", evaluate: (s) => (s.slaBreaches30 > 0 ? F(s.slaBreaches30, `${s.slaBreaches30} flaw(s) past the 30-day correction window.`) : P("Flaws corrected timely.")) },
      { id: "SI.L2-3.14.3", title: "Monitor security alerts & advisories (KEV)", evaluate: kevControl },
    ],
  },
  {
    id: "hipaa",
    name: "HIPAA Security Rule",
    short: "HIPAA",
    controls: [
      { id: "164.308(a)(1)(ii)(A)", title: "Risk Analysis", evaluate: () => P("Technical risk analysis maintained via continuous finding risk-ranking.") },
      {
        id: "164.308(a)(1)(ii)(B)",
        title: "Risk Management",
        evaluate: (s) => (s.highCritOpen > 0 ? F(s.highCritOpen, `${s.highCritOpen} high/critical risk(s) not reduced to a reasonable level.`) : P("High/critical risks reduced to a reasonable level.")),
      },
      { id: "164.308(a)(5)(ii)(B)", title: "Protection from Malicious Software", evaluate: kevControl },
      { id: "164.308(a)(8)", title: "Evaluation (periodic technical)", evaluate: (s) => scanCadence(s, s.scanOverdue90, "periodic") },
    ],
  },
  {
    id: "fedramp",
    name: "FedRAMP Moderate",
    short: "FedRAMP",
    controls: [
      {
        id: "RA-5",
        title: "Vulnerability Scanning (monthly)",
        evaluate: (s) =>
          s.lastScanDaysAgo === null
            ? F(1, "No completed scan on record — monthly scanning required.")
            : s.scanOverdue30
              ? F(1, `Last scan ${s.lastScanDaysAgo}d ago — FedRAMP requires monthly scanning.`)
              : P(`Last scan ${s.lastScanDaysAgo}d ago — within monthly cadence.`),
      },
      { id: "RA-5(2)/(4)", title: "Update & report scanned vulnerabilities (KEV)", evaluate: kevControl },
      {
        id: "SI-2",
        title: "Flaw Remediation (High 30d / Med 90d)",
        evaluate: (s) => {
          const failing = s.slaBreaches30 + s.slaBreachesMed90;
          return failing > 0
            ? F(failing, `${s.slaBreaches30} high past 30d · ${s.slaBreachesMed90} medium past 90d.`)
            : P("Remediation within FedRAMP timelines (High 30d, Med 90d).");
        },
      },
      { id: "CA-7", title: "Continuous Monitoring / POA&M", evaluate: (s) => (s.externalFailing > 0 ? F(s.externalFailing, `${s.externalFailing} internet-facing exposure(s) tracked as open POA&M items.`) : P("No open internet-facing exposures outstanding.")) },
    ],
  },
];

export function listFrameworks(): { id: string; name: string; short: string }[] {
  return FRAMEWORKS.map((f) => ({ id: f.id, name: f.name, short: f.short }));
}

const STATUS_WEIGHT: Record<ComplianceStatus, number> = {
  Pass: 1,
  Info: 1,
  "At Risk": 0.5,
  Fail: 0,
};

export function evaluateFramework(
  sig: ComplianceSignals,
  frameworkId: string,
): {
  framework: FrameworkDef;
  requirements: ComplianceRequirement[];
  score: number;
  overall: ComplianceStatus;
} {
  const framework = FRAMEWORKS.find((f) => f.id === frameworkId) ?? FRAMEWORKS[0];
  const requirements: ComplianceRequirement[] = framework.controls.map((c) => {
    const e = c.evaluate(sig);
    return { id: c.id, title: c.title, status: e.status, detail: e.detail, failing: e.failing };
  });
  const score = Math.round(
    (100 * requirements.reduce((a, r) => a + STATUS_WEIGHT[r.status], 0)) /
      Math.max(1, requirements.length),
  );
  const overall: ComplianceStatus = requirements.some((r) => r.status === "Fail")
    ? "Fail"
    : requirements.some((r) => r.status === "At Risk")
      ? "At Risk"
      : "Pass";
  return { framework, requirements, score, overall };
}
