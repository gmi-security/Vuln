"use client";
import { useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { SavedSource } from "@/lib/customer-saved-sources";
import type { CustomerSourceRead } from "@/lib/customer-source-read-model";
import { useCustomerCve } from "./customer-cve-context";

const names = { defender: "Microsoft Defender", crowdstrike: "CrowdStrike Spotlight" };
const button = "rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-100 hover:bg-zinc-800 disabled:opacity-40";
const missing = {
  "not-installed": "Saved results are not available yet.",
  "not-configured": "No saved connection is configured for this customer.",
  "no-completed-import": "Waiting for the first completed import. Counts are not available yet.",
  "summary-pending": "The import is complete. Its summary is waiting to be built; counts are not available yet.",
  "inconsistent": "Saved results could not be verified. Counts are withheld until the data is checked.",
};
function SourcePanel({companyId,source,showCves}:{companyId:string;source:SavedSource;showCves:boolean}) {
  const [data,setData]=useState<CustomerSourceRead|null>(null),[error,setError]=useState("");
  const [offset,setOffset]=useState(0),[refresh,setRefresh]=useState(0),[loading,setLoading]=useState(true);
  const openCve=useCustomerCve();
  useEffect(()=>{
    let active=true;setLoading(true);setError("");
    setData(old=>old?.state==="available" && old.cves.offset===offset ? old : null);
    dashboardRequest<CustomerSourceRead>(`customer-saved-sources?companyId=${encodeURIComponent(companyId)}&source=${source}&offset=${offset}`)
      .then(result=>{
        if(result.companyId!==companyId || result.source!==source)throw new Error("The returned results do not match this customer.");
        if(active)setData(result);
      }).catch(cause=>{if(active)setError(cause instanceof Error?cause.message:"Saved results are unavailable.");})
      .finally(()=>{if(active)setLoading(false);});
    return()=>{active=false;};
  },[companyId,source,offset,refresh]);
  const available=data?.state==="available"?data:null;
  return <section aria-label={`${names[source]} saved results`} className="min-w-0 rounded-xl border border-zinc-800 bg-[#090909] p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-lg font-semibold text-zinc-100">{names[source]}</h3>
      <button className={button} disabled={loading} onClick={()=>setRefresh(v=>v+1)}>Refresh saved results</button></div>
    <p className="mt-2 text-sm text-zinc-300">Saved source results. Sources are shown separately and are not added to platform totals.</p>
    {loading && <p role="status" className="mt-3 text-sm text-zinc-300">Loading saved results…</p>}
    {error && <p role="alert" className="mt-3 text-sm text-red-300">{error}{available?" Previously loaded results are shown below.":""}</p>}
    {data && data.state!=="available" && <p role="status" className="mt-4 text-sm text-amber-200">{missing[data.state]}</p>}
    {available && <>
      <div className="mt-4 space-y-2 text-sm text-zinc-300">
        <p>Import completed: {new Date(available.generation.completedAt).toLocaleString()}. This is the import time, not a device assessment time.</p>
        {available.generation.freshness!=="within-window" && <p role="status" className="text-amber-200">{available.generation.freshness==="stale"?"These results are older than 36 hours.":"The freshness of these results could not be verified."}</p>}
        {available.projection?.state==="pending" && <p role="status" className="text-amber-200">A newer import is waiting for its summary. Showing the previous completed results.</p>}
        {available.generation.revisionMatches===false && <p role="status" className="text-amber-200">The connection changed after this import. These results use the previous configuration.</p>}
        {available.latestAttempt?.status==="failed" && <p role="status" className="text-amber-200">The latest import failed. These are the last completed results.</p>}
        {(available.latestAttempt?.status==="queued" || available.latestAttempt?.status==="running") && <p role="status">Another import is {available.latestAttempt.status}. Completed results remain available.</p>}
      </div>
      <dl className="mt-5 grid grid-cols-2 gap-5 lg:grid-cols-4">
        {[["Open source instances",available.summary.sourceInstances],["Device / CVE findings",available.summary.deviceCveFindings],["Unique CVEs",available.summary.uniqueCves],["Affected devices",available.summary.affectedDevices]].map(([label,value])=><div key={label}><dt className="text-sm text-zinc-300">{label}</dt><dd className="mt-1 text-2xl font-semibold text-white">{Number(value).toLocaleString()}</dd></div>)}
      </dl>
      <p className="mt-4 text-sm text-zinc-300">{source==="defender"?"Instances count device, CVE and software version. Scores and severity use Microsoft CVSS.":"Instances count Spotlight findings. Scores and severity use CrowdStrike CVSS, not ExPRT. Confirmed suppressed findings are excluded."}</p>
      {source==="crowdstrike" && <p className="mt-2 text-sm text-zinc-300">Unknown suppression: {available.summary.unknownSuppressionInstances===null?"Unavailable":available.summary.unknownSuppressionInstances.toLocaleString()} instances. Excluded non-CVE entries: {available.summary.excludedNonCveInstances.toLocaleString()}.</p>}
      {showCves && <>
        <div className="mt-5 max-h-96 overflow-auto rounded-lg border border-zinc-800">
          <table className="w-full text-left text-sm"><caption className="p-3 text-left text-zinc-200">CVEs ordered by severity, then affected devices</caption>
            <thead className="sticky top-0 bg-zinc-900 text-zinc-200"><tr>{["CVE","Severity","CVSS","Affected devices"].map(v=><th key={v} className="whitespace-nowrap p-3">{v}</th>)}</tr></thead>
            <tbody>{available.cves.rows.map(row=><tr key={row.cve} className="border-t border-zinc-800 text-zinc-200"><td className="whitespace-nowrap p-3"><button className="text-sky-300 underline disabled:no-underline" disabled={!openCve} onClick={()=>openCve?.(row.cve)}>{row.cve}</button></td><td className="p-3">{row.severity}</td><td className="p-3">{row.cvss??"Unavailable"}</td><td className="p-3">{row.affectedDevices.toLocaleString()}</td></tr>)}</tbody>
          </table>
          {!available.cves.rows.length && <p className="p-3 text-sm text-zinc-300">No CVEs on this page.</p>}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-sm text-zinc-300"><span>{available.cves.rows.length?`${available.cves.offset+1}–${available.cves.offset+available.cves.rows.length}`:"0"} of {available.cves.total.toLocaleString()} CVEs</span>
          <button className={button} disabled={loading || offset===0} onClick={()=>setOffset(v=>Math.max(0,v-50))}>Previous CVEs</button>
          <button className={button} disabled={loading || offset+50>=available.cves.total || offset+50>1000000} onClick={()=>setOffset(v=>v+50)}>Next CVEs</button></div>
      </>}
    </>}
  </section>;
}
export default function CustomerSavedSources({companyId,showCves}:{companyId:string;showCves:boolean}) {
  const [sources,setSources]=useState<SavedSource[]|null>(null),[error,setError]=useState(""),[retry,setRetry]=useState(0);
  useEffect(()=>{
    let active=true;setSources(null);setError("");
    dashboardRequest<{companyId:string;sources:SavedSource[]}>(`customer-saved-sources?companyId=${encodeURIComponent(companyId)}`)
      .then(result=>{if(result.companyId!==companyId)throw new Error("The returned sources do not match this customer.");if(active)setSources(result.sources);})
      .catch(cause=>{if(active)setError(cause instanceof Error?cause.message:"Saved sources are unavailable.");});
    return()=>{active=false;};
  },[companyId,retry]);
  return <section aria-label="Saved source preview" className="space-y-4">
    <h2 className="text-xl font-semibold text-white">Saved source results</h2>
    {!sources && !error && <p role="status" className="text-sm text-zinc-300">Loading this customer's sources…</p>}
    {error && <div role="alert" className="text-sm text-red-300"><p>{error}</p><button className={button} onClick={()=>setRetry(v=>v+1)}>Retry saved sources</button></div>}
    {sources?.length===0 && <p className="text-sm text-zinc-300">Saved source preview is not enabled for this customer. Existing reporting remains available.</p>}
    {sources?.map(source=><SourcePanel key={`${companyId}:${source}`} companyId={companyId} source={source} showCves={showCves}/>)}
  </section>;
}
