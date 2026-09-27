"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { ExecReport } from "@/lib/store";
import styles from "./ReportingCustomer.module.css";

type Setup = { companies: { id: string; name: string }[] };
type Customer = { report: ExecReport; sources: { name: string; open: number }[] };
const number = (value: number) => value.toLocaleString();

export default function ReportingCustomer() {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [appCompanyId, setAppCompanyId] = useState("");
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    dashboardRequest<Setup>("reporting").then(data => { if (active) setSetup(data); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Reporting is unavailable."); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!appCompanyId) { setCustomer(null); return; }
    let active = true;
    setCustomer(null); setLoading(true); setError("");
    dashboardRequest<Customer>(`reporting?companyId=${encodeURIComponent(appCompanyId)}`)
      .then(data => { if (active) setCustomer(data); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Customer report is unavailable."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [appCompanyId]);

  const report = customer?.report;
  return <section aria-label="Customer report" className={styles.section}>
    <div className={styles.intro}>
      <div className={styles.introCopy}>
        <p className={styles.kicker}>Customer intelligence</p>
        <h2>Customer overview</h2>
        <p>One customer view across every connected scanner. Select a customer to inspect its current exposure and priorities.</p>
      </div>
      <label className={styles.selector}>Customer
        <select value={appCompanyId} onChange={event => setAppCompanyId(event.target.value)} disabled={!setup}>
          <option value="">Choose a customer</option>
          {setup?.companies.map(company => <option key={company.id} value={company.id}>{company.name} ({company.id})</option>)}
        </select>
      </label>
    </div>

    {!setup && !error && <p role="status" className={styles.status}>Loading customers...</p>}
    {setup && !setup.companies.length && <p role="status" className={styles.status}>No app customers are available yet.</p>}
    {error && <p role="alert" className={styles.error}>{error}</p>}
    {loading && <p role="status" className={styles.status}>Loading this customer&apos;s report...</p>}
    {!appCompanyId && setup?.companies.length ? <div className={styles.empty}>
      <span className={styles.emptyMark} aria-hidden="true">CO</span>
      <div><h3>Choose a customer to begin</h3><p>Findings, scanner coverage, and the full report will appear here.</p></div>
    </div> : null}

    {report && customer && <div className={styles.report}>
      <div className={styles.customerHeading}>
        <div><p className={styles.customerId}>{report.company.id}</p><h3>{report.company.name}</h3>
          <p className={styles.updated}>Updated {new Date(report.generatedAt).toLocaleString()}</p></div>
        <Link href={`/report/${encodeURIComponent(report.company.id)}`} className={styles.fullReport}>Open full report <span aria-hidden="true">↗</span></Link>
      </div>
      <div className={styles.metricGrid}>
        {[
          { label: "Open findings", value: number(report.findings.open), tone: "primary" },
          { label: "Critical open", value: number(report.findings.critical), tone: "critical" },
          { label: "Known exploited", value: number(report.findings.kevOpen), tone: "standard" },
          { label: "Exposure score", value: number(report.posture.exposureScore), tone: "standard" },
        ].map(metric => <div key={metric.label} className={`${styles.metric} ${metric.tone === "primary" ? styles.metricPrimary : metric.tone === "critical" ? styles.metricCritical : ""}`}>
          <span>{metric.label}</span><strong>{metric.value}</strong>
        </div>)}
      </div>
      <div className={styles.insights}>
        <section className={styles.insight} aria-label="Next priorities"><div className={styles.insightHeading}><h4>Next priorities</h4><span>{report.topRisks.length} listed</span></div>
          {report.topRisks.length ? <div className={styles.priorityScroll}><table className={styles.priorityTable}>
            <thead><tr><th>CVE</th><th>Finding</th><th>Risk</th></tr></thead>
            <tbody>{report.topRisks.map((risk, index) => <tr key={`${risk.cve}-${index}`}><td>{risk.cve}</td><td>{risk.title}</td><td>{risk.realRisk}</td></tr>)}</tbody>
          </table></div> : <p className={styles.emptyInsight}>No open priorities.</p>}
        </section>
        <section className={styles.insight} aria-label="Scanner coverage"><div className={styles.insightHeading}><h4>Scanner coverage</h4><span>{customer.sources.length} sources</span></div>
          <p className={styles.sourceNote}>Open findings observed by each source. A finding seen by multiple scanners appears under each source.</p>
          {customer.sources.length ? <div className={styles.sourceList}>{customer.sources.map(source => <div key={source.name} className={styles.sourceRow}><span>{source.name}</span><strong>{number(source.open)}</strong></div>)}</div>
            : <p className={styles.emptyInsight}>No open findings from a scanner.</p>}
        </section>
      </div>
    </div>}
  </section>;
}
