"use client";

import Link from "next/link";
import type { CustomerInsights } from "@/lib/reporting-insights";
import styles from "./QueryDashboard.module.css";

const format = (value: number) => value.toLocaleString();
const sourceName = (value: string) => value === "vulners" ? "Vulners" : value === "nessus" ? "Nessus" : value === "crowdstrike" ? "CrowdStrike" : value.replace(/\b\w/g, letter => letter.toUpperCase());
const date = (value: string | null) => value ? new Date(value).toLocaleDateString() : "—";
const severityColor: Record<string, string> = { Critical: "#b30e14", High: "#e05a35", Medium: "#d69a37", Low: "#4a86b8", Info: "#71717a" };

export default function CustomerScanViews({ companyId, companyName, insights }: { companyId: string; companyName: string; insights: CustomerInsights }) {
  const highestSeverity = Math.max(1, ...insights.severity.map(row => row.count));
  const highestSource = Math.max(1, ...insights.sources.map(row => row.open));
  return <section aria-label={`${companyName} scan views`} className="mt-8">
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div><p className="text-xs uppercase tracking-[0.25em] text-red-500">Customer data views</p>
        <h3 className="mt-2 text-xl font-semibold text-white">Scans and findings</h3>
        <p className="mt-1 text-sm text-zinc-400">{companyName} · {format(insights.totalScans)} scans · {format(insights.totalOpen)} open findings across this customer’s connected sources.</p></div>
      <Link className="text-sm text-red-300 underline underline-offset-4 hover:text-red-200" href={`/findings?company=${encodeURIComponent(companyId)}`}>View all findings</Link>
    </div>
    <div className={styles.board}>
      <article className={styles.tile} aria-label="Open findings by severity">
        <header className={styles.tileHeader}><div className={styles.tileHeading}><h4 className={styles.insightTitle}>Open findings by severity</h4><p className={styles.source}>All scanner findings · Open and in remediation</p></div></header>
        <div className={styles.tileContent}>
          {insights.totalOpen ? <div className={styles.insightBars}>{insights.severity.map(row => <div className={styles.insightBarRow} key={row.name}>
            <span className={styles.insightBarLabel}><i style={{ background: severityColor[row.name] }} />{row.name}</span>
            <div className={styles.insightBarTrack} aria-hidden="true"><span style={{ width: `${row.count / highestSeverity * 100}%`, background: severityColor[row.name] }} /></div>
            <strong>{format(row.count)}</strong>
          </div>)}</div> : <p className="py-5 text-sm text-zinc-400">No open findings recorded for this customer.</p>}
        </div>
        <footer className={styles.tileFooter}><span>All {format(insights.totalOpen)} open findings counted</span></footer>
      </article>
      <article className={styles.tile} aria-label="Scanner coverage">
        <header className={styles.tileHeader}><div className={styles.tileHeading}><h4 className={styles.insightTitle}>Scanner coverage</h4><p className={styles.source}>Sources recorded on this customer’s scans and findings</p></div></header>
        <div className={styles.tileContent}>
          {insights.sources.length ? <div className={styles.insightBars}>{insights.sources.map(row => <div className={styles.insightBarRow} key={row.name}>
            <span className={styles.insightBarLabel}>{sourceName(row.name)}</span>
            <div className={styles.insightBarTrack} aria-hidden="true"><span style={{ width: `${row.open / highestSource * 100}%` }} /></div>
            <strong>{format(row.open)} <small>open</small><small className={styles.insightScanCount}>{format(row.scans)} scans</small></strong>
          </div>)}</div> : <p className="py-5 text-sm text-zinc-400">No scans or findings recorded for this customer.</p>}
        </div>
        <footer className={styles.tileFooter}><span>One finding may be observed by multiple sources</span></footer>
      </article>
      <article className={`${styles.tile} ${styles.wide}`} aria-label="Highest risk findings">
        <header className={styles.tileHeader}><div className={styles.tileHeading}><h4 className={styles.insightTitle}>Highest risk findings</h4><p className={styles.source}>Review the affected asset and source before taking action</p></div>
          <span className={styles.insightCount}>Top {format(insights.highestRisk.length)} of {format(insights.totalOpen)}</span></header>
        <div className={styles.tileContent}>
          {insights.highestRisk.length ? <div role="region" aria-label="Scrollable highest risk findings" tabIndex={0} className={styles.tableScroll}>
            <table className={styles.table}><thead><tr><th scope="col">Finding</th><th scope="col">Affected asset</th><th scope="col">Severity</th><th scope="col">Source</th><th scope="col" className={styles.number}>Risk</th></tr></thead>
              <tbody>{insights.highestRisk.map(row => <tr key={row.id}>
                <td><Link className={styles.insightLink} href={`/findings?focus=${encodeURIComponent(row.id)}`}><strong>{row.cve}</strong><span>{row.title}</span></Link></td>
                <td>{row.asset}</td><td><span className={styles.insightSeverity} style={{ borderColor: severityColor[row.severity] }}>{row.severity}</span></td>
                <td>{row.connectors.map(sourceName).join(", ")}</td><td className={styles.number}>{format(row.realRisk)}</td>
              </tr>)}</tbody></table></div> : <p className="py-5 text-sm text-zinc-400">No open findings to review.</p>}
        </div>
        <footer className={styles.tileFooter}><span>Sorted by real risk · Open and in remediation</span><Link href={`/findings?company=${encodeURIComponent(companyId)}`}>All findings</Link></footer>
      </article>
      <article className={`${styles.tile} ${styles.wide}`} aria-label="Recent customer scans">
        <header className={styles.tileHeader}><div className={styles.tileHeading}><h4 className={styles.insightTitle}>Recent scans</h4><p className={styles.source}>Most recent scan activity for this customer</p></div>
          <span className={styles.insightCount}>Latest {format(insights.recentScans.length)} of {format(insights.totalScans)}</span></header>
        <div className={styles.tileContent}>
          {insights.recentScans.length ? <div role="region" aria-label="Scrollable recent scans" tabIndex={0} className={styles.tableScroll}>
            <table className={styles.table}><thead><tr><th scope="col">Scan</th><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Completed</th><th scope="col" className={styles.number}>Findings</th></tr></thead>
              <tbody>{insights.recentScans.map(row => <tr key={row.id}><td><Link className={styles.insightLink} href={`/scans/${encodeURIComponent(row.id)}`}><strong>{row.name}</strong></Link></td>
                <td>{sourceName(row.connector)}</td><td>{row.status}</td><td>{date(row.completedAt)}</td><td className={styles.number}>{format(row.findingsCount)}</td></tr>)}</tbody></table></div> : <p className="py-5 text-sm text-zinc-400">No scans recorded for this customer.</p>}
        </div>
        <footer className={styles.tileFooter}><span>Scan finding totals are reported by each scan</span><Link href="/scans">Browse scans</Link></footer>
      </article>
    </div>
  </section>;
}
