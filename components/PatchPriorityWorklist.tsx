"use client";
import {useEffect,useRef,useState} from "react";
import Link from "next/link";
import CveText from "./CveText";
import FixTicketStatus from "./FixTicketStatus";
import CompactPatchWorklist from "./CompactPatchWorklist";
import {dashboardRequest} from "@/lib/dashboard-browser-client";
import {priorityLabels,type PriorityWorklist,type PriorityRow} from "@/lib/patch-priority";
import styles from "./QueryDashboard.module.css";
type Result=PriorityWorklist&{companyId:string;calculatedAt:string};
const count=(n:number|null)=>n===null?"Unknown":n.toLocaleString();
const when=(value:string|null)=>value?new Date(value).toLocaleString():"Unknown";
const signal=(value:boolean|null)=>value===true?"Recorded":value===false?"Not marked":"Unknown";
const colors={1:"border-red-800 bg-red-950/60 text-red-200",2:"border-orange-800 bg-orange-950/40 text-orange-200",3:"border-amber-800 bg-amber-950/30 text-amber-200",4:"border-zinc-700 bg-zinc-900 text-zinc-200"};
function Cves({row}:{row:PriorityRow}){
  const [page,setPage]=useState(0),size=25;
  return <><p className="font-medium text-white">{row.cves.length.toLocaleString()} CVE{row.cves.length===1?"":"s"}</p>
    {row.cves.length===1?<CveText text={row.cves[0]}/>:<details className="mt-2"><summary className="cursor-pointer text-sky-300">Review CVEs and affected devices</summary>
      <div className="my-2 max-h-48 space-y-2 overflow-auto">{row.cves.slice(page*size,(page+1)*size).map(cve=><div key={cve}><CveText text={cve}/></div>)}</div>
      {row.cves.length>size&&<div className="flex items-center gap-3 text-xs"><button disabled={!page} onClick={()=>setPage(p=>p-1)} className="underline disabled:opacity-40">Previous</button>
        <span>{page*size+1}–{Math.min((page+1)*size,row.cves.length)}</span><button disabled={(page+1)*size>=row.cves.length} onClick={()=>setPage(p=>p+1)} className="underline disabled:opacity-40">Next</button></div>}
    </details>}
    <p className="mt-2 text-xs text-zinc-300">{row.products.length?row.products.join(" · "):"Product: unknown — review source evidence"}</p>
    <p className="mt-2 text-xs text-zinc-400">{row.sources.map(s=>s==="crowdstrike"?"CrowdStrike":"Platform findings").join(" + ")}</p></>;
}
export default function PatchPriorityWorklist({companyId,canManage}:{companyId:string;canManage:boolean}){
  const [data,setData]=useState<Result|null>(null),[grouping,setGrouping]=useState<"byCve"|"byRemediation">("byRemediation");
  const [loading,setLoading]=useState(true),[error,setError]=useState(""),[version,setVersion]=useState(0),[busy,setBusy]=useState<string|null>(null);
  const [message,setMessage]=useState<{id:string;text:string;error:boolean}|null>(null),alive=useRef(true),inFlight=useRef(false);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  useEffect(()=>{
    let active=true;
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),45000);setLoading(true);setError("");
    dashboardRequest<Result>(`patch-priority?companyId=${encodeURIComponent(companyId)}`,{signal:controller.signal})
      .then(result=>{if(result.companyId!==companyId)throw Error("Worklist returned a different customer.");if(!controller.signal.aborted)setData(result);})
      .catch(cause=>{if(active)setError(controller.signal.aborted?"Priority worklist took too long. Try Refresh.":cause instanceof Error?cause.message:"Could not load the worklist.");})
      .finally(()=>{clearTimeout(timeout);if(active)setLoading(false);});
    return()=>{active=false;clearTimeout(timeout);controller.abort();};
  },[companyId,version]);
  async function prepare(row:PriorityRow){
    if(inFlight.current)return;inFlight.current=true;setBusy(row.id);setMessage(null);
    try{const result=await dashboardRequest<{companyId:string;groups:{id:string}[]}>("remediation-ticket",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({companyId,id:row.id})});
      if(result.companyId!==companyId||!result.groups?.length)throw Error("No draft was confirmed. Check Tickets before retrying.");
      if(alive.current){setMessage({id:row.id,text:`${result.groups.length} draft${result.groups.length===1?"":"s"} prepared for review.`,error:false});setVersion(v=>v+1);}}
    catch(cause){if(alive.current)setMessage({id:row.id,text:cause instanceof Error?cause.message:"Could not prepare draft.",error:true});}
    finally{inFlight.current=false;if(alive.current)setBusy(null);}
  }
  const current=data?.companyId===companyId?data:null,rows=current?.[grouping]??[],total=grouping==="byCve"?current?.totalCves:current?.totalRemediations;
  return <><section aria-label="Risk-based patch worklist" aria-busy={loading} className="rounded-2xl border border-red-900/60 bg-[#080808] p-5 sm:p-7">
    <div className="flex flex-wrap items-start justify-between gap-4"><div><p className="text-xs uppercase tracking-[0.2em] text-red-400">New · patch planning</p>
      <h2 className="mt-2 text-2xl font-semibold text-white">Risk-based patch worklist</h2><p className="mt-2 max-w-4xl text-sm text-zinc-300">Urgency first, then affected devices, then earliest recorded due date. Click a CVE to review devices and required fixes.</p></div>
      <button className={styles.button} disabled={loading} onClick={()=>setVersion(v=>v+1)}>{loading?"Loading…":"Refresh worklist"}</button></div>
    <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label="Group patch worklist">
      {(["byRemediation","byCve"] as const).map(mode=><button key={mode} aria-pressed={grouping===mode} onClick={()=>{setGrouping(mode);setMessage(null);}}
        className={`rounded-lg border px-4 py-2 text-sm font-medium ${grouping===mode?"border-red-800 bg-red-950/50 text-white":"border-zinc-700 text-zinc-300 hover:bg-zinc-900"}`}>{mode==="byCve"?"By CVE":"By remediation"}</button>)}
    </div>
    <details className="mt-4 text-sm text-zinc-300"><summary className="cursor-pointer text-zinc-100">How priority is assigned</summary><p className="mt-2 max-w-5xl leading-relaxed">
      Urgent: recorded KEV or observed exploitation. High: Critical/High severity, CVSS ≥ 7, a public exploit, EPSS ≥ 10%, or verified exposed/critical assets.
      Review: evidence needed for a routine decision is missing. Routine: no elevated signal in complete recorded evidence. This is a transparent GMI review policy, not an official SSVC classification or a ConnectWise SLA priority.
      A group takes its most urgent finding; missing evidence remains visible. Cached threat signals can be older than the latest source situation.</p></details>
    {error&&<p role="alert" className="mt-4 text-red-300">{error}{current?" Previously loaded results are shown.":""}</p>}
    {current?.notices.map(note=><p key={note} role="status" className="mt-3 text-sm text-amber-200">{note}</p>)}
    {!current&&loading&&<p role="status" className="mt-5 text-zinc-300">Loading saved priority summaries…</p>}
    {current&&<><p className="mt-4 text-sm text-zinc-300">Showing {rows.length.toLocaleString()} of {total?.toLocaleString()} {grouping==="byCve"?"CVEs":"remediation groups"}. Counts cover available sources.</p>
      {!rows.length?<p className="mt-5 text-zinc-300">No open CVE evidence is available in the completed summaries.</p>:<div tabIndex={0} aria-label="Scrollable patch priority table" className="mt-4 max-h-[38rem] overflow-auto rounded-xl border border-zinc-800">
      <table className="w-full min-w-[1750px] text-left text-sm"><thead className="sticky top-0 z-10 bg-[#1a1a1a] text-zinc-100"><tr>
        {["Priority + reason","CVE / affected product","Severity / CVSS","Exploitation evidence","EPSS","Affected devices","Recommended remediation","Owner / due date","Ticket coverage","Last observed"].map(label=><th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}
      </tr></thead><tbody>{rows.map(row=><tr key={row.id} className="border-t border-zinc-800 align-top text-zinc-200 hover:bg-zinc-900/40">
        <td className="min-w-56 px-4 py-4"><span className={`inline-block rounded-md border px-2 py-1 font-semibold ${colors[row.urgency]}`}>{priorityLabels[row.urgency]}</span>
          <ul className="mt-2 space-y-1 text-xs">{row.reasons.map(reason=><li key={reason}>{reason}</li>)}</ul>{!!row.gaps.length&&<details className="mt-3 text-xs text-amber-200"><summary className="cursor-pointer">Evidence gaps ({row.gaps.length})</summary><ul className="mt-2 space-y-1">{row.gaps.map(gap=><li key={gap}>{gap}</li>)}</ul></details>}</td>
        <td className="min-w-56 max-w-80 px-4 py-4"><Cves row={row}/></td>
        <td className="min-w-36 px-4 py-4"><strong>{row.severity}</strong><p className="mt-1">CVSS {row.cvss===null?"Unknown":row.cvss.toFixed(1)}</p><p className="mt-2 text-xs text-zinc-300">{row.cvssSources.join("; ")||"Score source unknown"}</p></td>
        <td className="min-w-48 space-y-2 px-4 py-4 text-xs"><p>KEV: {signal(row.kev)}</p><p>Observed exploitation: {signal(row.active)}</p><p>Public exploit: {signal(row.publicExploit)}</p></td>
        <td className="px-4 py-4"><strong>{row.epss===null?"Unknown":`${(row.epss*100).toFixed(2)}%`}</strong><p className="mt-1 text-xs text-zinc-300">Maximum recorded probability</p></td>
        <td className="min-w-40 px-4 py-4"><strong className="text-xl text-white">{row.deviceCountIsLowerBound?"≥ ":""}{count(row.deviceCount)}</strong><p className="mt-2 text-xs">Exposed: {count(row.exposedDevices)}</p><p className="mt-1 text-xs">Critical: {count(row.criticalDevices)}</p>
          {row.deviceCountIsLowerBound&&<p className="mt-2 text-xs text-amber-200">Lower bound; device identities or source overlap are incomplete.</p>}<p className="mt-2 text-xs text-zinc-300">{row.findingCount.toLocaleString()} findings</p></td>
        <td className="min-w-72 max-w-md px-4 py-4">{grouping==="byCve"&&<p className="mb-2 text-xs text-zinc-300">Example recorded fix. Click the CVE to review all required updates and devices.</p>}<p className="max-h-32 overflow-auto whitespace-pre-wrap break-words">{row.remediation||"Unknown"}</p>
          {!!row.missingRemediation&&<p className="mt-2 text-xs text-amber-200">{row.missingRemediation.toLocaleString()} findings have no recorded fix.</p>}
          {grouping==="byRemediation"&&row.source==="platform"&&<p className="mt-2 text-xs text-zinc-300">Exact saved fix within one CVE; no shared vendor patch identity is assumed.</p>}
          {grouping==="byRemediation"&&canManage&&<button className={`${styles.button} mt-3`} disabled={loading||!!busy||!!error} onClick={()=>void prepare(row)}>{busy===row.id?"Preparing…":"Prepare ticket draft"}</button>}
          {message?.id===row.id&&<div role={message.error?"alert":"status"} className={`mt-2 text-xs ${message.error?"text-red-300":"text-emerald-200"}`}>{message.text}{!message.error&&<Link href={`/remediation?companyId=${encodeURIComponent(companyId)}&view=tickets`} className="mt-2 block underline">Review on Tickets</Link>}</div>}</td>
        <td className="min-w-44 px-4 py-4"><p>{row.owners.length?row.owners.join(", "):"Unassigned / unknown"}</p>{row.unassignedFindings>0&&<p className="mt-1 text-xs text-zinc-300">{row.unassignedFindings.toLocaleString()} findings unassigned</p>}
          <p className={`mt-2 ${row.dueAt&&Date.parse(row.dueAt)<Date.now()?"text-red-300":""}`}>{row.dueAt?`${Date.parse(row.dueAt)<Date.now()?"Overdue · ":"Due · "}${new Date(row.dueAt).toLocaleDateString()}`:"Due date: unknown"}</p><p className="mt-1 text-xs text-zinc-300">Platform finding SLA; not a CW deadline.</p></td>
        <td className="min-w-64 px-4 py-4"><FixTicketStatus status={row.ticketStatus} companyId={companyId}/></td>
        <td className="min-w-48 px-4 py-4 text-xs"><p>Finding: {when(row.lastObserved)}</p><p className="mt-2">Threat cache: {when(row.threatObserved)}</p></td>
      </tr>)}</tbody></table></div>}
      <p className="mt-3 text-xs leading-relaxed text-zinc-300">Device counts are unique within each source group. CVE rows spanning source inventories show a lower bound, not a summed estate total. Threat values are group maxima or any recorded positive signal; review individual CVEs before acting. Existing tickets describe planned work, not confirmed resolution. CSVs and ticket contents are prepared through the existing review workflow.</p>
    </>}
  </section><CompactPatchWorklist key={companyId} companyId={companyId} canManage={canManage} data={current} loading={loading} error={error} busy={busy} message={message}
    refresh={()=>setVersion(v=>v+1)} prepare={prepare}/></>;
}
