"use client";
import {useEffect,useRef,useState} from "react";
import Link from "next/link";
import {priorityLabels,type PriorityRow,type PriorityWorklist} from "@/lib/patch-priority";
import {filterPatchWorklist,type PatchWorklistFilters} from "@/lib/patch-worklist-filters";
import FixTicketStatus,{ticketStatusLabels} from "./FixTicketStatus";
import CveText from "./CveText";
import {useCustomerCve} from "./customer-cve-context";

type Grouping="byRemediation"|"byCve";
type Props={
  companyId:string;canManage:boolean;data:(PriorityWorklist&{companyId:string;calculatedAt:string})|null;
  loading:boolean;error:string;busy:string|null;message:{id:string;text:string;error:boolean}|null;
  refresh:()=>void;prepare:(row:PriorityRow)=>Promise<void>;
};
const button="rounded-lg border border-zinc-700 px-3 py-2 text-sm font-medium text-zinc-100 hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50";
const control="mt-1 w-full rounded-lg border border-zinc-700 bg-[#141414] px-3 py-2 text-sm text-zinc-100";
const colors={1:"border-red-800 bg-red-950/60 text-red-200",2:"border-orange-800 bg-orange-950/40 text-orange-200",3:"border-amber-800 bg-amber-950/30 text-amber-200",4:"border-zinc-700 bg-zinc-900 text-zinc-200"};
const count=(value:number|null)=>value===null?"Unknown":value.toLocaleString();
const signal=(value:boolean|null)=>value===true?"Recorded":value===false?"Not marked":"Unknown";
const when=(value:string|null)=>value?new Date(value).toLocaleString():"Unknown";
const percent=(value:number|null)=>value===null?"Unknown":`${(value*100).toFixed(2)}%`;
function Priority({row}:{row:PriorityRow}) {
  return <span className={`inline-block rounded-md border px-2 py-1 text-xs font-semibold ${colors[row.urgency]}`}>{priorityLabels[row.urgency]}</span>;
}

function Review({row,grouping,close,...props}:Props&{row:PriorityRow;grouping:Grouping;close:()=>void}) {
  const dialog=useRef<HTMLDialogElement>(null),openCve=useCustomerCve();
  const [page,setPage]=useState(0),size=25,lastPage=Math.max(0,Math.ceil(row.cves.length/size)-1),currentPage=Math.min(page,lastPage);
  useEffect(()=>{dialog.current?.showModal();},[]);
  return <dialog ref={dialog} aria-labelledby="compact-review-title" onClose={close}
    className="fixed inset-y-0 left-auto right-0 m-0 h-dvh max-h-dvh w-full max-w-2xl overflow-y-auto border-l border-zinc-700 bg-[#0c0c0c] p-6 text-zinc-200 shadow-2xl backdrop:bg-black/70">
    <div className="flex items-start justify-between gap-4"><div><p className="text-xs uppercase tracking-widest text-red-400">Saved customer evidence</p>
      <h3 id="compact-review-title" className="mt-2 text-xl font-semibold text-white">{grouping==="byCve"?row.cves[0]:"Review recommended fix"}</h3></div>
      <button autoFocus className={button} onClick={()=>dialog.current?.close()}>Close</button></div>
    <div className="mt-5"><Priority row={row}/><ul className="mt-3 space-y-1 text-sm">{row.reasons.map(reason=><li key={reason}>{reason}</li>)}</ul></div>
    <dl className="mt-5 grid grid-cols-2 gap-3 rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 text-sm">
      {[["Severity",row.severity],["Maximum CVSS",row.cvss===null?"Unknown":row.cvss.toFixed(1)],["CISA KEV",signal(row.kev)],["Observed exploitation",signal(row.active)],
        ["Public exploit",signal(row.publicExploit)],["Maximum EPSS",percent(row.epss)],["Affected devices",`${row.deviceCountIsLowerBound?"At least ":""}${count(row.deviceCount)}`],
        ["Exposed / business-critical devices",`${count(row.exposedDevices)} / ${count(row.criticalDevices)}`]].map(([label,value])=><div key={label}><dt className="text-zinc-400">{label}</dt><dd className="mt-1 font-medium text-zinc-100">{value}</dd></div>)}
    </dl>
    <p className="mt-3 text-xs text-zinc-300">CVSS source: {row.cvssSources.join("; ")||"Unknown"}. EPSS estimates exploitation probability within 30 days. Values describe group maxima or any recorded positive signal.</p>
    <h4 className="mt-6 font-semibold text-white">{grouping==="byCve"?"Example recorded remediation":"Recommended remediation"}</h4>
    <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-relaxed">{row.remediation||"No remediation recorded."}</p>
    {grouping==="byCve"&&<p className="mt-2 text-sm text-amber-200">A CVE can require several different updates. Open its details below to review all fixes and prepare a request.</p>}
    {grouping==="byRemediation"&&row.source==="platform"&&<p className="mt-2 text-xs text-zinc-300">Exact saved fix within one CVE; a shared vendor patch identity is not assumed.</p>}
    {!!row.missingRemediation&&<p className="mt-2 text-sm text-amber-200">{count(row.missingRemediation)} findings have no recorded fix.</p>}
    <h4 className="mt-6 font-semibold text-white">CVEs and affected products</h4>
    <p className="mt-2 text-sm">{row.products.join(" · ")||"Product unknown"}</p>
    <p className="mt-2 text-xs text-zinc-300">{count(row.cves.length)} CVEs · {count(row.findingCount)} findings. Select a CVE to inspect devices and source evidence.</p>
    <div className="mt-3 flex max-h-44 flex-wrap gap-2 overflow-auto">{row.cves.slice(currentPage*size,(currentPage+1)*size).map(cve=><button key={cve} className={`${button} text-sky-300`} disabled={!openCve}
      onClick={()=>{dialog.current?.close();openCve?.(cve);}}>{cve}</button>)}</div>
    {row.cves.length>size&&<div className="mt-3 flex items-center gap-3 text-xs"><button className={button} disabled={!currentPage} onClick={()=>setPage(currentPage-1)}>Previous CVEs</button>
      <span>{currentPage*size+1}–{Math.min((currentPage+1)*size,row.cves.length)} of {count(row.cves.length)}</span><button className={button} disabled={currentPage>=lastPage} onClick={()=>setPage(currentPage+1)}>Next CVEs</button></div>}
    <h4 className="mt-6 font-semibold text-white">Ticket coverage</h4><FixTicketStatus status={row.ticketStatus} companyId={props.companyId}/>
    <p className="mt-3 text-xs text-zinc-300">Check existing requests and devices before preparing another draft. This does not create a ticket in ConnectWise; review and send from Tickets.</p>
    <div className="mt-4 flex flex-wrap gap-3">
      {grouping==="byRemediation"&&props.canManage&&<button className={`${button} border-red-800 bg-red-950/50`} disabled={props.loading||!!props.error||!!props.busy}
        onClick={()=>void props.prepare(row)}>{props.busy===row.id?"Preparing…":"Prepare ticket draft"}</button>}
      <Link className={button} href={`/remediation?companyId=${encodeURIComponent(props.companyId)}&view=tickets`}>Open Tickets</Link>
    </div>
    {props.message?.id===row.id&&<p role={props.message.error?"alert":"status"} className={`mt-3 text-sm ${props.message.error?"text-red-300":"text-emerald-200"}`}>{props.message.text}</p>}
    {(props.loading||props.error)&&<p role="status" className="mt-3 text-sm text-amber-200">{props.error||"Refreshing evidence. Draft preparation is paused until it finishes."}</p>}
    <dl className="mt-6 space-y-3 border-t border-zinc-800 pt-4 text-sm">
      <div><dt className="text-zinc-400">Owner / due date</dt><dd>{row.owners.join(", ")||"Unassigned / unknown"} · {when(row.dueAt)}</dd>
        <dd className="text-xs text-zinc-300">{count(row.unassignedFindings)} findings unassigned. Platform finding SLA, not a ConnectWise deadline.</dd></div>
      <div><dt className="text-zinc-400">Last observed / threat cache</dt><dd>{when(row.lastObserved)} / {when(row.threatObserved)}</dd></div>
      <div><dt className="text-zinc-400">Source</dt><dd>{row.sources.map(s=>s==="crowdstrike"?"CrowdStrike":"Platform findings").join(" + ")}</dd></div>
    </dl>
    {!!row.gaps.length&&<div className="mt-5 rounded-lg border border-amber-900 p-3 text-sm text-amber-200"><h4 className="font-semibold">Evidence gaps</h4><ul className="mt-2 space-y-1">{row.gaps.map(gap=><li key={gap}>{gap}</li>)}</ul></div>}
    {row.deviceCountIsLowerBound&&<p className="mt-3 text-sm text-amber-200">Device count is a lower bound. Device identities or overlap between source inventories are incomplete.</p>}
  </dialog>;
}

export default function CompactPatchWorklist(props:Props) {
  const [grouping,setGrouping]=useState<Grouping>("byRemediation"),[selected,setSelected]=useState<string|null>(null);
  const [filters,setFilters]=useState<PatchWorklistFilters>({search:"",severity:"all",signal:"all",ticket:"all"});
  const current=props.data?.companyId===props.companyId?props.data:null,loaded=current?.[grouping]??[];
  const rows=filterPatchWorklist(loaded,filters),review=loaded.find(row=>row.id===selected);
  const total=grouping==="byCve"?current?.totalCves:current?.totalRemediations;
  return <section id="compact-patch-worklist" aria-label="Compact patch worklist" aria-busy={props.loading} className="rounded-2xl border border-red-900/60 bg-[#090909] p-5 sm:p-7">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-xs uppercase tracking-[0.2em] text-red-400">New layout · Live customer data</p>
      <h2 className="mt-2 text-2xl font-semibold text-white">Compact patch worklist</h2><p className="mt-2 text-sm text-zinc-300">Find a priority, review its evidence, then prepare a ticket draft. Same ranking and saved evidence as the worklist above.</p></div>
      <button className={button} disabled={props.loading} onClick={props.refresh}>{props.loading?"Loading…":"Refresh worklists"}</button></header>
    <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label="Group compact worklist">{(["byRemediation","byCve"] as const).map(mode=><button key={mode} aria-pressed={grouping===mode}
      className={`${button} ${grouping===mode?"border-red-700 bg-red-950/50":""}`} onClick={()=>{setGrouping(mode);setSelected(null);}}>{mode==="byCve"?"By CVE":"By remediation"}</button>)}</div>
    <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-[2fr_1fr_1fr_1fr]">
      <label className="text-xs text-zinc-300">Search loaded results<input type="search" value={filters.search} onChange={e=>setFilters({...filters,search:e.target.value})} className={control} placeholder="CVE, product or recommended fix"/></label>
      <label className="text-xs text-zinc-300">Severity<select value={filters.severity} onChange={e=>setFilters({...filters,severity:e.target.value})} className={control}><option value="all">All severities</option>{["Critical","High","Medium","Low","Info","None","Unknown"].map(s=><option key={s} value={s}>{s}</option>)}</select></label>
      <label className="text-xs text-zinc-300">Exploitation evidence<select value={filters.signal} onChange={e=>setFilters({...filters,signal:e.target.value as PatchWorklistFilters["signal"]})} className={control}><option value="all">All evidence</option><option value="kev">CISA KEV recorded</option><option value="active">Observed exploitation</option><option value="publicExploit">Public exploit recorded</option></select></label>
      <label className="text-xs text-zinc-300">Ticket coverage<select value={filters.ticket} onChange={e=>setFilters({...filters,ticket:e.target.value as PatchWorklistFilters["ticket"]})} className={control}><option value="all">All ticket states</option>{Object.entries(ticketStatusLabels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
    </div>
    <p className="mt-3 text-xs text-zinc-300">Search and filters apply only to the loaded top {loaded.length||50} {grouping==="byCve"?"CVEs":"remediation groups"}, not the full customer inventory. Priority order is unchanged.</p>
    {props.error&&<p role="alert" className="mt-3 text-sm text-red-300">{props.error}{current?" Previously loaded results are shown; draft preparation is paused.":""}</p>}
    {current?.notices.map(note=><p key={note} role="status" className="mt-3 text-sm text-amber-200">{note}</p>)}
    {props.message&&<p role={props.message.error?"alert":"status"} className={`mt-3 text-sm ${props.message.error?"text-red-300":"text-emerald-200"}`}>{props.message.text}{!props.message.error&&<> <Link href={`/remediation?companyId=${encodeURIComponent(props.companyId)}&view=tickets`} className="underline">Review on Tickets</Link></>}</p>}
    {!current&&props.loading&&<p role="status" className="mt-5 text-zinc-300">Loading saved customer worklist…</p>}
    {current&&<><div className="mt-5 flex flex-wrap items-center justify-between gap-3 text-xs text-zinc-300"><p>{rows.length} shown · {loaded.length} loaded · {total?.toLocaleString()} total groups</p>
      <button className="underline" onClick={()=>setFilters({search:"",severity:"all",signal:"all",ticket:"all"})}>Clear filters</button></div>
      {!rows.length?<p role="status" className="mt-5 text-zinc-300">{loaded.length?"No loaded results match these filters.":"No open CVE evidence is available in the completed summaries."}</p>:
      <div tabIndex={0} aria-label="Scrollable compact patch table" className="mt-3 max-h-[36rem] overflow-auto rounded-xl border border-zinc-800">
        <table className="w-full min-w-[1050px] text-left text-sm"><thead className="sticky top-0 z-10 bg-[#1a1a1a] text-zinc-100"><tr>{["Priority / reason",grouping==="byCve"?"CVE / affected product":"Recommended fix / CVEs","Severity / evidence","Devices","Ticket coverage","Review"].map(label=><th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}</tr></thead>
          <tbody>{rows.map(row=><tr key={row.id} className="border-t border-zinc-800 align-top text-zinc-200 hover:bg-zinc-900/60">
            <td className="w-44 px-4 py-4"><Priority row={row}/><p className="mt-2 text-xs">{row.reasons[0]}</p>{!!row.gaps.length&&<p className="mt-1 text-xs text-amber-200">{row.gaps.length} evidence gaps</p>}</td>
            <td className="max-w-md px-4 py-4">{grouping==="byCve"?<><CveText text={row.cves[0]}/><p className="mt-2 line-clamp-2 text-xs text-zinc-300">{row.products.join(" · ")||"Product unknown"}</p></>:
              <><p className="line-clamp-2 font-medium text-white">{row.remediation||"Remediation unknown"}</p><p className="mt-2 text-xs"><CveText text={row.cves.slice(0,2).join(", ")}/>{row.cves.length>2&&` +${row.cves.length-2} more`}</p></>}
              <p className="mt-2 text-xs text-zinc-400">{row.sources.map(s=>s==="crowdstrike"?"CrowdStrike":"Platform findings").join(" + ")}</p></td>
            <td className="px-4 py-4"><strong>{row.severity}</strong><p className="mt-1 text-xs">CVSS {row.cvss===null?"Unknown":row.cvss.toFixed(1)} · EPSS {percent(row.epss)}</p>
              <p className="mt-2 text-xs text-zinc-300">KEV: {signal(row.kev)}<br/>Observed: {signal(row.active)}<br/>Public exploit: {signal(row.publicExploit)}</p></td>
            <td className="px-4 py-4"><strong className="text-xl text-white">{row.deviceCountIsLowerBound?"≥ ":""}{count(row.deviceCount)}</strong><p className="mt-2 text-xs text-zinc-300">{count(row.findingCount)} findings</p>{row.deviceCountIsLowerBound&&<p className="mt-1 text-xs text-amber-200">Lower bound</p>}</td>
            <td className="max-w-60 px-4 py-4"><p className="font-medium">{ticketStatusLabels[row.ticketStatus?.state??"unavailable"]}</p>
              {row.ticketStatus?.coverage?<p className="mt-2 text-xs text-zinc-300">{count(row.ticketStatus.coverage.coveredDevices)} / {count(row.ticketStatus.coverage.totalDevices)} covered<br/>{count(row.ticketStatus.coverage.remainingDevices)} need coverage review</p>:
                row.ticketStatus?.state==="open"&&<p className="mt-2 text-xs text-amber-200">Device coverage unverified</p>}
              {row.ticketStatus?.tickets.filter(t=>t.ticketId).slice(0,2).map(t=><p key={t.id} className="mt-2 text-xs">{t.url?<a className="text-sky-300 underline" href={t.url} target="_blank" rel="noopener noreferrer">CW #{t.ticketId}</a>:`CW #${t.ticketId}`}{!t.sameFix&&" (related CVE)"}</p>)}</td>
            <td className="px-4 py-4"><button className={button} onClick={()=>setSelected(row.id)} aria-label={`Review ${grouping==="byCve"?row.cves[0]:row.remediation}`}>Review →</button></td>
          </tr>)}</tbody></table></div>}
      <p className="mt-3 text-xs leading-relaxed text-zinc-300">Counts cover available sources. Devices are unique within each source group; cross-source CVE totals can be lower bounds. Existing tickets describe planned work, not confirmed resolution. Summary calculated {when(current.calculatedAt)}.</p>
    </>}
    {review&&<Review key={`${grouping}:${review.id}`} {...props} row={review} grouping={grouping} close={()=>setSelected(null)}/>}
  </section>;
}
