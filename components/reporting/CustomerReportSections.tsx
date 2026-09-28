"use client";

import Link from "next/link";
import type { CustomerReportingModel } from "@/lib/reporting-customer-model";
import styles from "../QueryDashboard.module.css";

const format = (value: number) => value.toLocaleString();
const label = (value: string) => value === "vulners" ? "Vulners" : value === "nessus" ? "Nessus" :
  value === "nmap" ? "Nmap" : value.replace(/\b\w/g, letter => letter.toUpperCase());
const observed = (value: string | null) => value ? new Date(value).toLocaleString() : "No successful observation recorded";
const severityColors: Record<string, string> = { Critical: "#b30e14", High: "#e05a35", Medium: "#d69a37", Low: "#4a86b8", Info: "#71717a" };

function Metric({ name, value, note }: { name: string; value: string; note: string }) {
  return <div className="rounded-xl border border-zinc-800 bg-black p-4">
    <p className="text-xs text-zinc-400">{name}</p><strong className="mt-2 block text-3xl font-semibold tabular-nums text-white">{value}</strong>
    <p className="mt-2 text-xs text-zinc-500">{note}</p>
  </div>;
}

function FindingTable({ rows, title, companyId, total, kind = "vuln" }: {
  rows: CustomerReportingModel["priorityRows"]; title: string; companyId: string; total: number; kind?: "vuln" | "osint" | "pentest" | "all";
}) {
  const listHref = `/findings?company=${encodeURIComponent(companyId)}&kind=${kind}`;
  return <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label={title}>
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3"><div><h3 className="text-lg font-semibold text-white">{title}</h3>
      <p className="mt-1 text-sm text-zinc-400">Showing {format(rows.length)} of {format(total)} recorded findings</p></div>
      <Link className="text-sm text-red-300 underline underline-offset-4" href={listHref}>View all findings</Link></div>
    {rows.length ? <div className={styles.tableScroll} role="region" tabIndex={0} aria-label={`${title} table`}><table className={styles.table}>
      <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>Source</th><th>Status</th><th>Risk</th><th>Last seen</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.id}><td><Link className="text-zinc-100 underline underline-offset-2" href={`${listHref}&focus=${encodeURIComponent(row.id)}`}>{row.cve || row.title}</Link><span className="block max-w-xs truncate text-xs text-zinc-500">{row.title}</span></td>
        <td>{row.asset}</td><td>{row.severity}</td><td>{row.connectors.map(label).join(", ")}</td><td>{row.status}</td>
        <td className="tabular-nums">{format(row.realRisk)}</td><td>{observed(row.lastSeen)}</td></tr>)}</tbody>
    </table></div> : <p className="text-sm text-zinc-400">No findings in this section.</p>}
  </section>;
}

export default function CustomerReportSections({ model }: { model: CustomerReportingModel }) {
  const { company, metrics, sourceActivity, assets } = model;
  const lastObserved = sourceActivity.map(row => row.lastObservedAt).filter((value): value is string => Boolean(value)).sort().at(-1) ?? null;
  const severities = Object.entries(metrics.vulnerabilities.bySeverity);
  const maxSeverity = Math.max(1, ...severities.map(([, count]) => count));
  return <div className="mt-6 space-y-6" aria-label={`${company.name} report sections`}>
    <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-xl font-semibold text-white">{company.name}</h3>
        <p className="mt-1 text-xs text-zinc-400">{company.id} · Latest recorded source observation: {observed(lastObserved)}</p></div>
        <span className={`rounded-full border px-3 py-1 text-xs ${model.assessmentState === "assessed" ? "border-emerald-800 text-emerald-300" : "border-amber-800 text-amber-300"}`}>
          {model.assessmentState === "assessed" ? "Assessment data available" : "No vulnerability assessment recorded"}</span></div>
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Metric name="Open remediation findings" value={model.assessmentState === "assessed" ? format(metrics.vulnerabilities.open) : "—"} note="Stored vulnerability and web-test findings" />
        <Metric name="Critical open" value={model.assessmentState === "assessed" ? format(metrics.vulnerabilities.critical) : "—"} note="Critical remediation findings" />
        <Metric name="Known exploited" value={model.assessmentState === "assessed" ? format(metrics.vulnerabilities.kev) : "—"} note="CISA KEV marked findings" />
        <Metric name="Attack-surface exposures" value={format(metrics.attackSurface.open)} note="Separate from remediation findings" />
        <Metric name="Known inventory assets" value={format(assets.inventoryCount)} note="Inventory count, not scan coverage" />
      </div>
    </section>

    <div className="grid gap-5 xl:grid-cols-2">
      <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Open remediation findings by severity">
        <h3 className="text-lg font-semibold text-white">Severity distribution</h3><p className="mt-1 text-sm text-zinc-400">Open remediation findings; each correlated finding is counted once.</p>
        {model.assessmentState === "assessed" ? <div className="mt-5 space-y-3">{severities.map(([name, count]) => <div key={name} className="grid grid-cols-[5rem_1fr_4rem] items-center gap-3 text-sm">
          <span>{name}</span><div className="h-2 rounded-full bg-zinc-800" aria-hidden="true"><div className="h-2 rounded-full" style={{ width: `${count / maxSeverity * 100}%`, background: severityColors[name] }} /></div>
          <strong className="text-right tabular-nums">{format(count)}</strong></div>)}</div> : <p className="mt-5 text-sm text-zinc-400">No completed vulnerability assessment or open remediation finding is recorded.</p>}
      </section>
      <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Recorded findings history">
        <h3 className="text-lg font-semibold text-white">Recorded history</h3><p className="mt-1 text-sm text-zinc-400">Stored company snapshots over the past 180 days, when available.</p>
        {model.history.length ? <div className={`${styles.tableScroll} mt-4 max-h-64`} role="region" tabIndex={0} aria-label="Recorded history table"><table className={styles.table}><thead><tr><th>Observed</th><th>Recorded open findings</th></tr></thead>
          <tbody>{model.history.slice(-12).map((point, index) => <tr key={`${point.ts}-${index}`}><td>{observed(point.ts)}</td><td className="tabular-nums">{point.open === null ? "Unavailable" : format(point.open)}</td></tr>)}</tbody></table></div> : <p className="mt-5 text-sm text-zinc-400">No recorded history yet. Current findings are still shown above.</p>}
      </section>
    </div>

    <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Customer source activity"><h3 className="text-lg font-semibold text-white">Source activity</h3>
      <p className="mt-1 text-sm text-zinc-400">Sources observed for this customer. One finding can be reported by multiple scanners, so source counts can overlap.</p>
      {sourceActivity.length ? <div className={`${styles.tableScroll} mt-4`} role="region" tabIndex={0} aria-label="Source activity table"><table className={styles.table}><thead><tr><th>Source</th><th>Evidence</th><th>Scans</th><th>Open observations</th><th>Scan state</th><th>Last observed</th></tr></thead>
        <tbody>{sourceActivity.map(row => <tr key={row.source}><td>{label(row.source)}</td><td>{row.evidence}</td><td className="tabular-nums">{format(row.scanCount)}</td><td className="tabular-nums">{format(row.openObservations)}</td>
          <td>{[row.runningCount && `${row.runningCount} running`, row.failedCount && `${row.failedCount} failed`, row.completedCount && `${row.completedCount} completed`].filter(Boolean).join(" · ") || "No scan"}</td><td>{observed(row.lastObservedAt)}</td></tr>)}</tbody></table></div> : <p className="mt-5 text-sm text-zinc-400">No scanner or inventory source has recorded data for this customer.</p>}
    </section>

    <FindingTable rows={model.priorityRows} title="Highest risk vulnerability findings" companyId={company.id} total={model.priorityTotal} />
    <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Recent customer scans"><h3 className="text-lg font-semibold text-white">Recent scans</h3>
      <p className="mt-1 text-sm text-zinc-400">Showing {format(model.recentScans.length)} of {format(model.scanTotal)} recorded scans. Failed or unfinished scans are not evidence of zero findings.</p>
      {model.recentScans.length ? <div className={`${styles.tableScroll} mt-4`} role="region" tabIndex={0} aria-label="Recent scans table"><table className={styles.table}><thead><tr><th>Scan</th><th>Source</th><th>Status</th><th>Completed</th><th>Imported findings</th></tr></thead>
        <tbody>{model.recentScans.map(scan => <tr key={scan.id}><td><Link className="text-zinc-100 underline underline-offset-2" href={`/scans/${encodeURIComponent(scan.id)}`}>{scan.name}</Link></td><td>{label(scan.connector)}</td><td>{scan.status}</td><td>{observed(scan.completedAt)}</td><td className="tabular-nums">{scan.status === "Completed" ? format(scan.findingsCount) : "—"}</td></tr>)}</tbody></table></div> : <p className="mt-5 text-sm text-zinc-400">No scans recorded for this customer.</p>}
    </section>

    <section className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Asset context"><h3 className="text-lg font-semibold text-white">Asset context</h3>
      <p className="mt-2 text-sm text-zinc-400">{format(assets.inventoryCount)} known inventory assets. {assets.contextCoveragePercent === null ? "No open remediation findings to assess inventory context." : `${format(assets.authoritativeFindingCount)} open remediation findings (${assets.contextCoveragePercent}%) use authoritative inventory context.`} This does not measure scan coverage.</p>
    </section>
    {metrics.attackSurface.open > 0 && <FindingTable rows={model.attackSurfaceRows} title="Attack-surface exposures" companyId={company.id} total={metrics.attackSurface.open} kind="osint" />}
    {metrics.webTesting.open > 0 && <FindingTable rows={model.webTestingRows} title="Web application testing" companyId={company.id} total={metrics.webTesting.open} kind="pentest" />}
  </div>;
}
