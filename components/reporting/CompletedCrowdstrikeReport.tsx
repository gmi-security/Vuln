"use client";

import Link from "next/link";
import CveText from "../CveText";
import type { CustomerReportingModel } from "@/lib/reporting-customer-model";
import type { ReportingCrowdstrike } from "@/lib/customer-source-read-model";
import styles from "../QueryDashboard.module.css";

const names: Record<string,string> = {CRITICAL:"Critical",HIGH:"High",MEDIUM:"Medium",LOW:"Low",NONE:"None",UNKNOWN:"Unknown"};
const colors: Record<string,string> = {CRITICAL:"#b30e14",HIGH:"#e05a35",MEDIUM:"#d69a37",LOW:"#4a86b8",NONE:"#71717a",UNKNOWN:"#a1a1aa"};
const missing = {
  "not-installed":"Completed-import summaries are not available yet.",
  "not-configured":"This customer's CrowdStrike connection is unavailable.",
  "no-completed-import":"Waiting for the first completed CrowdStrike import. Counts are unavailable.",
  "summary-pending":"Waiting for the completed import's summary. Current counts are unavailable.",
  "inconsistent":"The saved import could not be verified against this customer's connection. Counts are unavailable.",
};
const format = (n:number) => n.toLocaleString();

export default function CompletedCrowdstrikeReport({model,data}:{model:CustomerReportingModel;data:ReportingCrowdstrike}) {
  const current=data.state==="available"?data:null;
  const pairSeverity=current?.summary.severity.deviceCveFindings;
  const severity=pairSeverity?Object.entries(pairSeverity):[];
  const maximum=Math.max(1,...severity.map(([,count])=>count));
  return <section className="space-y-5" aria-label="Completed CrowdStrike report">
    <div className="rounded-xl border border-zinc-800 bg-[#090909] p-5">
      <h3 className="text-xl font-semibold text-white">{model.company.name}</h3>
      <p className="mt-1 text-sm text-zinc-300">{model.company.id} · CrowdStrike Spotlight · Last completed import</p>
      {!current && <p role="status" className="mt-4 text-sm text-amber-200">{data.state==="unavailable"?data.message:data.state!=="available"?missing[data.state]:""}</p>}
      {current && <>
        <p className="mt-2 text-sm text-zinc-300">Import completed: <time dateTime={current.generation.completedAt}>{new Date(current.generation.completedAt).toLocaleString()}</time>. This is the import completion time, not each device's assessment time.</p>
        {current.generation.freshness!=="within-window" && <p role="status" className="mt-2 text-amber-200">{current.generation.freshness==="stale"?"These completed results are older than 36 hours.":"The freshness of these results could not be verified."}</p>}
        {current.projection?.state==="pending" && <p role="status" className="mt-2 text-amber-200">A newer import is awaiting its summary. These counts describe the previous completed summary.</p>}
        {current.latestAttempt && current.latestAttempt.status!=="succeeded" && <p role="status" className="mt-2 text-zinc-300">Latest import: {current.latestAttempt.status}. The last completed results remain shown.</p>}
        <dl className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[["Open CrowdStrike findings",current.summary.deviceCveFindings],["Critical open",pairSeverity?.CRITICAL??null],["Unique CVEs",current.summary.uniqueCves],["Affected devices",current.summary.affectedDevices]].map(([name,value])=><div key={name} className="rounded-xl border border-zinc-800 bg-black p-4"><dt className="text-sm text-zinc-300">{name}</dt><dd className="mt-2 text-3xl font-semibold tabular-nums text-white">{value===null?"Unavailable":format(Number(value))}</dd></div>)}
        </dl>
        <p className="mt-4 text-sm text-zinc-300">Each device/CVE combination counts once, matching the CrowdStrike count in the trend. Open and reopened CVE findings are included; confirmed suppressed findings are excluded. These counts do not include other scanners.</p>
        <p className="mt-2 text-xs text-zinc-400">{format(current.summary.sourceInstances)} source instances before device/CVE deduplication. Unknown suppression: {current.summary.unknownSuppressionInstances===null?"unavailable":format(current.summary.unknownSuppressionInstances)} source instances. KEV and platform risk are not calculated in this summary.</p>
      </>}
      <div className="mt-5 flex flex-wrap gap-5 text-sm text-zinc-300"><span>Platform attack-surface exposures: <strong>{format(model.metrics.attackSurface.open)}</strong></span><span>Known inventory assets: <strong>{format(model.assets.inventoryCount)}</strong> (inventory, not scan coverage)</span></div>
    </div>
    {current && <>
      <div className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="CrowdStrike severity distribution">
        <h3 className="text-lg font-semibold text-white">Open CrowdStrike findings by severity</h3>
        <p className="mt-1 text-sm text-zinc-300">Counts add up to the headline total. Each CVE uses its highest recorded CrowdStrike CVSS severity across affected devices, not ExPRT.</p>
        {!pairSeverity && <p role="status" className="mt-4 text-sm text-amber-200">Severity breakdown is unavailable.</p>}
        <div className="mt-5 space-y-3">{severity.map(([name,count])=><div key={name} className="grid grid-cols-[5rem_1fr_7rem] items-center gap-3 text-sm text-zinc-200"><span>{names[name]??name}</span><div className="h-2 rounded-full bg-zinc-800" aria-hidden="true"><div className="h-2 rounded-full" style={{width:`${count/maximum*100}%`,background:colors[name]}}/></div><strong className="text-right tabular-nums">{format(count)}</strong></div>)}</div>
      </div>
      <div className="rounded-xl border border-zinc-800 bg-[#090909] p-5" aria-label="Completed import CVEs">
        <h3 className="text-lg font-semibold text-white">CrowdStrike CVEs by severity and affected devices</h3>
        <p className="mt-1 text-sm text-zinc-300">Showing {format(current.cves.rows.length)} of {format(current.cves.total)} unique CVEs from this completed import. Devices can occur under multiple CVEs.</p>
        <div className={`${styles.tableScroll} mt-4 max-h-96`} role="region" tabIndex={0} aria-label="Completed CrowdStrike CVEs"><table className={styles.table}>
          <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Affected devices</th><th>Source instances</th></tr></thead>
          <tbody>{current.cves.rows.map(row=><tr key={row.cve}><td><CveText text={row.cve}/></td><td>{names[row.severity]}</td><td>{row.cvss??"Unknown"}</td><td>{format(row.affectedDevices)}</td><td>{format(row.sourceInstances)}</td></tr>)}</tbody>
        </table></div>
        {!current.cves.total && <p className="mt-3 text-sm text-zinc-300">No open CVEs in this completed import.</p>}
        <Link className="mt-4 inline-block text-sm text-red-300 underline" href={`/remediation?companyId=${encodeURIComponent(model.company.id)}&view=prioritize`}>Review patch worklist and affected devices</Link>
      </div>
    </>}
  </section>;
}
