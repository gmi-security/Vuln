"use client";
import CveText from "./CveText";
import { useEffect, useRef, useState } from "react";
import type { RemediationWorklist as Worklist } from "@/lib/remediation-worklist";

import { dashboardRequest } from "@/lib/dashboard-browser-client";
import Link from "next/link";
import styles from "./QueryDashboard.module.css";

export default function RemediationWorklist({ data, loading, companyId, canManage }: { data: Worklist | undefined; loading: boolean; companyId:string; canManage:boolean }) {
  const live=useRef(true),inFlight=useRef(false);
  const [busy,setBusy]=useState<string|null>(null),[message,setMessage]=useState<{id:string;error?:string;count?:number}|null>(null);
  useEffect(()=>{live.current=true;return()=>{live.current=false;};},[]);
  async function prepare(id:string) {
    if(inFlight.current)return;
    inFlight.current=true;setBusy(id);setMessage(null);
    try {
      const result=await dashboardRequest<{companyId:string;groups:{id:string}[]}>("remediation-ticket",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({companyId,id})});
      if(result.companyId!==companyId || !Array.isArray(result.groups) || !result.groups.length)throw new Error("The server did not confirm this customer's draft. Check the Tickets page before retrying.");
      if(live.current)setMessage({id,count:result.groups.length});
    }catch(cause){if(live.current)setMessage({id,error:cause instanceof Error?cause.message:"Could not prepare the draft. Check the Tickets page before retrying."});}
    finally {inFlight.current=false;if(live.current)setBusy(null);}
  }
  const [expanded,setExpanded]=useState<{id:string;offset:number}|null>(null);
  const pageSize=50;
  return <section className="mt-6 rounded-2xl border border-zinc-800 bg-[#050505] p-5 sm:p-7" aria-label="Recommended remediation worklist" aria-busy={loading}>
    <h2 className="text-2xl font-semibold text-white">Remediations by severity and device impact</h2>
    <p className="mt-2 max-w-4xl text-sm text-zinc-300">Highest severity first, then most unique affected devices. Each CrowdStrike row shares one recommended action and target version across the listed CVEs. Different versions stay separate.</p>
    <p className="mt-2 text-xs text-zinc-300">Use this table to choose patch work. Prepare a ticket draft for the selected recommended fix, then review and approve it on the Tickets page before sending to ConnectWise. Click a CVE to review its evidence. Rows include open findings even when tickets exist; they do not represent unticketed work or confirmed resolution.</p>
    {!data && <p className="mt-5 text-sm text-zinc-300" role="status">{loading ? "Loading remediation worklist…" : "The remediation summary is not available yet."}</p>}
    {data?.notices?.map(notice=><p key={notice} role="status" className="mt-3 text-sm text-amber-200">{notice}</p>)}
    {data && <>
      <p className="mt-4 text-sm text-zinc-300">Showing {data.rows.length.toLocaleString()} of {data.totalGroups.toLocaleString()} remediation groups.</p>
      {!data.rows.length && !data.notices?.length && <p className="mt-4 text-sm text-zinc-300">No open findings with recorded remediation are available for this customer.</p>}
      {!!data.rows.length && <div className="mt-4 max-h-[36rem] overflow-auto rounded-xl border border-zinc-800" tabIndex={0} aria-label="Scrollable remediation table">
        <table className="w-full min-w-[780px] text-left text-sm">
          <thead className="sticky top-0 z-10 bg-[#171717] text-zinc-200"><tr>
            {["Severity","Recommended remediation","Unique devices","CVEs covered","Source / highest risk",...(canManage?["Patch request"]:[])].map(label=><th key={label} scope="col" className="px-4 py-3 font-medium">{label}</th>)}
          </tr></thead>
          <tbody>{data.rows.map(row=>{
            const open=expanded?.id===row.id, offset=Math.min(expanded?.offset ?? 0,Math.max(0,Math.floor((row.cves.length-1)/pageSize)*pageSize));
            return <tr key={row.id} className="border-t border-zinc-800 align-top">
            <td className="px-4 py-4"><span className={row.severity==="Critical" ? "font-semibold text-red-300" : row.severity==="High" ? "font-semibold text-orange-300" : "text-zinc-200"}>{row.severity}</span></td>
            <td className="max-w-xl px-4 py-4"><p className="max-h-28 overflow-auto whitespace-pre-wrap break-words text-white">{row.remediation}</p>{row.reference && <p className="mt-2 break-words text-xs text-zinc-300">{row.reference}</p>}</td>
            <td className="px-4 py-4 text-xl font-semibold tabular-nums text-white">{row.deviceCount.toLocaleString()}</td>
            <td className="min-w-52 px-4 py-4"><button type="button" className="text-zinc-100 underline underline-offset-2" aria-expanded={open}
              onClick={()=>setExpanded(open?null:{id:row.id,offset:0})}>{open?"Hide":"View"} {row.cves.length.toLocaleString()} CVE{row.cves.length===1?"":"s"}</button>
              {open && <><div className="mt-2 max-h-40 space-y-1 overflow-auto">{row.cves.slice(offset,offset+pageSize).map(cve=><p key={cve}><CveText text={cve}/></p>)}</div>
                {row.cves.length>pageSize && <div className="mt-2 space-y-2 text-xs text-zinc-200">
                  <p>{offset+1}–{Math.min(offset+pageSize,row.cves.length)} of {row.cves.length.toLocaleString()}</p>
                  <div className="flex gap-3"><button type="button" disabled={offset===0} className="underline disabled:opacity-40" onClick={()=>setExpanded({id:row.id,offset:offset-pageSize})}>Previous CVEs</button>
                    <button type="button" disabled={offset+pageSize>=row.cves.length} className="underline disabled:opacity-40" onClick={()=>setExpanded({id:row.id,offset:offset+pageSize})}>Next CVEs</button></div>
                </div>}
              </>}
              {row.grouping==="single-cve" && <p className="mt-2 text-xs text-zinc-300">Single-CVE evidence; no shared vendor patch ID.</p>}</td>
            <td className="px-4 py-4 text-zinc-200">{row.source==="crowdstrike" ? "CrowdStrike · GMI patch score" : "Platform risk"}<strong className="mt-1 block tabular-nums">{row.maxRisk.toLocaleString()}</strong><p className="mt-1 text-xs text-zinc-300">{row.findingCount.toLocaleString()} findings</p></td>
            {canManage && <td className="min-w-56 px-4 py-4">
              <button type="button" className={styles.button} disabled={!!busy || loading} onClick={()=>void prepare(row.id)}>{busy===row.id?"Preparing draft...":"Prepare ticket draft"}</button>
              {message?.id===row.id && (message.error?<p role="alert" className="mt-2 text-sm text-red-300">{message.error}</p>:<div role="status" className="mt-2 text-sm text-zinc-200">
                <p>{message.count} draft{message.count===1?"":"s"} ready for review.</p>
                <Link className="mt-2 inline-block underline" href={`/remediation?companyId=${encodeURIComponent(companyId)}&view=tickets`}>Review on Tickets page</Link>
              </div>)}
            </td>}
          </tr>;})}</tbody>
        </table>
      </div>}
      <p className="mt-3 text-xs text-zinc-300">Devices are counted once within each action and source. A device may need several actions. Counts across sources are not deduplicated. Platform sources without a shared vendor patch ID remain grouped within one CVE. Risk scores break ties within a source.</p>
    </>}
  </section>;
}
