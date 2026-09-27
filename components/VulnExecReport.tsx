"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import ReportingNav from "@/components/ReportingNav";
import TrendChart, { type TrendSnapshot } from "@/components/TrendChart";
import { compositeColor } from "@/lib/format";
import styles from "./VulnExecReport.module.css";

const SLA_SEVERITIES = ["Critical", "High", "Medium", "Low"] as const;
type SlaSummary = { bySeverity: Partial<Record<string, { open: number; overdue: number }>>; mttrDays: number | null };
type ExecReport = {
  generatedAt: string;
  company: { id: string; name: string; industry: string };
  posture: { compositeScore: number; compositeBand: string; exposureScore: number };
  findings: { open: number; critical: number; high: number; kevOpen: number };
  ssvc: { act: number; attend: number; overdue: number; kevOverdue: number };
  compliance: { framework: string; overall: string; score: number }[];
  attackSurface: { total: number; exposedAssets: number; leakedCredentials: number; webVulnerabilities: number };
  financial: { ale: number };
  topRisks: { cve: string; title: string; asset: string; realRisk: number; decision: string; kev: boolean }[];
  sla?: SlaSummary | null;
  trend?: TrendSnapshot[] | null;
};
type SendResult = { kind: "sent" | "skipped" | "error"; message: string };

function money(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${Math.round(n / 1_000)}K`;
  return `$${n}`;
}

function ReportMetric({ label, value, emphasis = false }: { label: string; value: string | number; emphasis?: boolean }) {
  return <div className={`${styles.metric} ${emphasis ? styles.metricEmphasis : ""}`}><span>{label}</span><strong>{value}</strong></div>;
}

export default function VulnExecReport({ companyId }: { companyId: string }) {
  const [report, setReport] = useState<ExecReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sendPhase, setSendPhase] = useState<"idle" | "confirm" | "sending">("idle");
  const [sendResult, setSendResult] = useState<SendResult | null>(null);

  async function sendReportEmail() {
    setSendPhase("sending"); setSendResult(null);
    try {
      const res = await fetch(`/api/report/${companyId}/send`, { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (res.ok) setSendResult({ kind: "sent", message: `Sent to ${json.to}${json.cc?.length ? ` (cc ${json.cc.join(", ")})` : ""}` });
      else if (res.status === 400 || res.status === 503) setSendResult({ kind: "skipped", message: json.error ?? `Not sent (HTTP ${res.status}).` });
      else setSendResult({ kind: "error", message: json.error ?? `Send failed (HTTP ${res.status}).` });
    } catch { setSendResult({ kind: "error", message: "Failed to reach the API. Report not sent." }); }
    setSendPhase("idle");
  }

  useEffect(() => {
    let active = true;
    void fetch(`/api/report/${companyId}`, { cache: "no-store" })
      .then(async response => {
        if (!response.ok) throw new Error((await response.json()).error ?? "Failed to load report.");
        return response.json();
      })
      .then(payload => { if (active) setReport({ ...payload.report, sla: payload.report?.sla ?? payload.sla ?? null, trend: payload.report?.trend ?? payload.trend ?? null }); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Failed to load report."); });
    return () => { active = false; };
  }, [companyId]);

  const date = report ? new Date(report.generatedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : "";
  return <div className={styles.page}>
    <div className={styles.chrome}><ReportingNav />
      <div className={styles.toolbar}>
        <div><Link href="/reporting" className={styles.back}>← Reporting</Link><p>Customer report</p></div>
        {report && <div className={styles.toolbarActions}>
          {sendPhase === "confirm" ? <div className={styles.confirm} role="group" aria-label="Confirm report email">
            <span>Email this report to the customer contact?</span>
            <button type="button" className={styles.sendButton} onClick={() => void sendReportEmail()}>Confirm send</button>
            <button type="button" className={styles.ghostButton} onClick={() => setSendPhase("idle")}>Cancel</button>
          </div> : <button type="button" className={styles.ghostButton} disabled={sendPhase === "sending" || sendResult?.kind === "skipped"} onClick={() => { setSendResult(null); setSendPhase("confirm"); }}>{sendPhase === "sending" ? "Sending..." : "Email to customer"}</button>}
          <button type="button" className={styles.printButton} onClick={() => window.print()}>Print / Save as PDF</button>
        </div>}
      </div>
      {sendResult && <p role="status" className={`${styles.sendResult} ${sendResult.kind === "error" ? styles.sendError : sendResult.kind === "sent" ? styles.sendSuccess : ""}`}>{sendResult.message}</p>}
    </div>

    {error && <div role="alert" className={styles.pageState}>{error}</div>}
    {!error && !report && <div role="status" className={styles.pageState}>Loading customer report...</div>}
    {report && <article className={styles.paper} aria-label={`${report.company.name} report`}>
      <header className={styles.reportHeader}>
        <div><p className={styles.reportLabel}>GMI Security / Executive report</p><h1>{report.company.name}</h1>
          <p className={styles.reportIndustry}>{report.company.industry || "Vulnerability and compliance posture"}</p></div>
        <div className={styles.reportMeta}><span>{date}</span><span>{report.company.id}</span><strong>Confidential</strong></div>
      </header>

      <section aria-label="Security posture" className={styles.posture}>
        <div className={styles.score} style={{ borderColor: compositeColor(report.posture.compositeScore) }}>
          <span>Composite risk</span><strong style={{ color: compositeColor(report.posture.compositeScore) }}>{report.posture.compositeScore}</strong>
          <small>of 100</small><b style={{ color: compositeColor(report.posture.compositeScore) }}>{report.posture.compositeBand}</b>
          <span className={styles.exposureScore}>Exposure score <strong>{report.posture.exposureScore.toLocaleString()}</strong></span>
        </div>
        <div className={styles.summaryGrid}>
          <ReportMetric label="Open findings" value={report.findings.open.toLocaleString()} />
          <ReportMetric label="Critical open" value={report.findings.critical.toLocaleString()} emphasis />
          <ReportMetric label="High open" value={report.findings.high.toLocaleString()} />
          <ReportMetric label="Actively exploited (KEV)" value={report.findings.kevOpen.toLocaleString()} emphasis={report.findings.kevOpen > 0} />
          <ReportMetric label="SSVC: Act now" value={report.ssvc.act.toLocaleString()} emphasis={report.ssvc.act > 0} />
          <ReportMetric label="SSVC: Attend" value={report.ssvc.attend.toLocaleString()} />
          <ReportMetric label="Past remediation SLA" value={report.ssvc.overdue.toLocaleString()} emphasis={report.ssvc.overdue > 0} />
          <ReportMetric label="KEV past SLA" value={report.ssvc.kevOverdue.toLocaleString()} emphasis={report.ssvc.kevOverdue > 0} />
          <ReportMetric label="Est. annual risk exposure" value={money(report.financial.ale)} />
        </div>
      </section>

      <div className={styles.reportColumns}>
        <section className={styles.reportSection} aria-label="Compliance posture"><div className={styles.sectionHeading}><h2>Compliance posture</h2><span>{report.compliance.length} frameworks</span></div>
          {report.compliance.length ? <div className={styles.complianceList}>{report.compliance.map(item => <div key={item.framework} className={styles.complianceRow}>
            <span>{item.framework}</span><strong>{item.score}</strong><small className={item.overall === "Pass" ? styles.good : item.overall === "Fail" ? styles.bad : styles.neutral}>{item.overall}</small>
          </div>)}</div> : <p className={styles.empty}>No compliance assessments yet.</p>}
        </section>
        <section className={styles.reportSection} aria-label="External attack surface"><div className={styles.sectionHeading}><h2>External attack surface</h2><span>OSINT</span></div>
          <div className={styles.surfaceGrid}>
            <ReportMetric label="Total exposures" value={report.attackSurface.total.toLocaleString()} />
            <ReportMetric label="Exposed assets" value={report.attackSurface.exposedAssets.toLocaleString()} />
            <ReportMetric label="Leaked credentials" value={report.attackSurface.leakedCredentials.toLocaleString()} emphasis={report.attackSurface.leakedCredentials > 0} />
            <ReportMetric label="Web weaknesses" value={report.attackSurface.webVulnerabilities.toLocaleString()} />
          </div>
        </section>
      </div>

      {report.sla && <section className={styles.reportSection} aria-label="SLA performance"><div className={styles.sectionHeading}><h2>SLA performance</h2><span>Open findings by severity</span></div>
        <div className={styles.slaLayout}><div className={styles.tableScroll}><table className={styles.dataTable}>
          <thead><tr><th>Severity</th><th>Open</th><th>Past SLA</th></tr></thead>
          <tbody>{SLA_SEVERITIES.map(severity => { const row = report.sla?.bySeverity?.[severity] ?? { open: 0, overdue: 0 }; return <tr key={severity}><td>{severity}</td><td>{row.open.toLocaleString()}</td><td className={row.overdue > 0 ? styles.bad : styles.good}>{row.overdue.toLocaleString()}</td></tr>; })}</tbody>
        </table></div><div className={styles.mttr}><strong>{report.sla.mttrDays != null ? `${report.sla.mttrDays}d` : "N/A"}</strong><span>Mean time to remediate</span></div></div>
      </section>}

      {(report.trend?.length ?? 0) >= 2 && <section className={styles.reportSection} aria-label="Findings trend"><div className={styles.sectionHeading}><h2>Open findings trend</h2><span>Last 90 days</span></div><div className={styles.chart}><TrendChart snapshots={report.trend ?? []} theme="light" /></div></section>}

      <section className={styles.reportSection} aria-label="Top priorities"><div className={styles.sectionHeading}><h2>Top priorities</h2><span>{report.topRisks.length} listed</span></div>
        <div className={styles.tableScroll}><table className={styles.dataTable}>
          <thead><tr><th>Action</th><th>Finding</th><th>Asset</th><th>Risk</th></tr></thead>
          <tbody>{report.topRisks.map((risk, index) => <tr key={`${risk.cve}-${index}`}><td><strong className={risk.decision === "Act" ? styles.bad : styles.neutral}>{risk.decision}</strong>{risk.kev && <span className={styles.kev}>KEV</span>}</td>
            <td><strong>{risk.cve}</strong><span className={styles.findingTitle}>{risk.title}</span></td><td>{risk.asset}</td><td><strong style={{ color: compositeColor(risk.realRisk) }}>{risk.realRisk}</strong></td></tr>)}
            {!report.topRisks.length && <tr><td colSpan={4}>No open priorities. The queue is clear.</td></tr>}
          </tbody>
        </table></div>
      </section>

      <footer className={styles.methodology}><strong>How this report is calculated</strong><p>Prioritization uses CISA SSVC (Act, Attend, Track) from exploitation signals (CISA KEV, EPSS, public exploits), exposure, and asset criticality. Estimated annual risk exposure is an ALE model: single loss expectancy by severity multiplied by an annual rate of occurrence weighted by exploitation and exposure. It is an order of magnitude planning figure, not an actuarial value. Generated by the GMI Vuln console.</p></footer>
    </article>}
  </div>;
}
