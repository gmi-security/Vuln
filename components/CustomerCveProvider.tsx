"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { CustomerCveContext } from "./customer-cve-context";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { readCustomerCve, prepareCustomerCve } from "@/lib/customer-cve-service";
import type { PatchGroup } from "@/lib/patch-request";
import ConnectWiseGroupTicket from "./ConnectWiseGroupTicket";
import styles from "./QueryDashboard.module.css";

type Detail=Awaited<ReturnType<typeof readCustomerCve>> & {scope?:"published-defender-cohort";enrichmentState?:"available"|"unavailable"|"not-recorded"};
type Packet=Awaited<ReturnType<typeof prepareCustomerCve>>;
function download(group:PatchGroup) {
  const url=URL.createObjectURL(new Blob([group.csv],{type:"text/csv;charset=utf-8"}));
  const anchor=document.createElement("a");anchor.href=url;anchor.download=`${group.label}-patch-request.csv`;anchor.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function Draft({entry,companyId}:{entry:Packet["groups"][number];companyId:string}) {
  const [approved,setApproved]=useState(false),[error,setError]=useState(""),[busy,setBusy]=useState(false);
  async function approve() {
    setBusy(true);setError("");
    try {await dashboardRequest(`patch-group-tickets/${entry.id}?companyId=${encodeURIComponent(companyId)}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"approve"})});setApproved(true);}
    catch(error){setError(error instanceof Error?error.message:"Approval failed.");}finally{setBusy(false);}
  }
  return <section className="rounded-xl border border-zinc-700 p-4">
    <h3 className="font-semibold">{entry.group.title}</h3>
    <p className="my-2 text-sm text-zinc-300">{entry.group.deviceCount.toLocaleString()} devices · {entry.group.findingCount.toLocaleString()} findings</p>
    <p className="whitespace-pre-wrap text-sm">{entry.group.action}</p>
    <button className={`${styles.button} my-3`} onClick={()=>download(entry.group)}>Download host CSV</button>
    <details><summary className="cursor-pointer text-sm">Ticket contents</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg bg-black p-3 text-sm text-zinc-200">{entry.group.ticketBody}</pre></details>
    {!approved && <button className={`${styles.button} mt-3`} disabled={busy} onClick={()=>void approve()}>{busy?"Approving…":"Approve draft for manual sending"}</button>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <ConnectWiseGroupTicket key={`${entry.id}:${approved}`} group={entry.group} requestId={entry.id} customerScope={companyId}/>
  </section>;
}
function Panel({companyId,cve,canManage,compareEnabled,close}:{companyId:string;cve:string;canManage:boolean;compareEnabled:boolean;close:()=>void}) {
  const dialog=useRef<HTMLDialogElement>(null), live=useRef(true), generation=useRef(0);
  const [comparison,setComparison]=useState(false);
  const [detail,setDetail]=useState<Detail|null>(null),[packet,setPacket]=useState<Packet|null>(null),[error,setError]=useState(""),[busy,setBusy]=useState(false);
  useEffect(()=>{
    let active=true;live.current=true;dialog.current?.showModal();
    const version=++generation.current;
    setDetail(null);setPacket(null);setError("");setBusy(false);
    const endpoint=comparison?"customer-cve-comparison":"customer-cve";
    dashboardRequest<Detail>(`${endpoint}?companyId=${encodeURIComponent(companyId)}&cve=${encodeURIComponent(cve)}`)
      .then(data=>{if(active&&version===generation.current){
        if(data.companyId!==companyId||data.cve!==cve||(comparison&&data.scope!=="published-defender-cohort"))throw new Error("CVE response did not match the selected customer and view.");
        setDetail(data);
      }})
      .catch(error=>{if(active&&version===generation.current)setError(error.message);});
    return()=>{active=false;live.current=false;};
  },[companyId,cve,comparison]);
  function switchMode(){generation.current++;setDetail(null);setPacket(null);setError("");setBusy(false);setComparison(value=>!value);}
  async function prepare() {
    if(comparison)return;
    const version=generation.current;
    setBusy(true);setError("");
    try {const data=await dashboardRequest<Packet>("customer-cve",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({companyId,cve})});
      if(live.current && version===generation.current && data.companyId===companyId && data.cve===cve)setPacket(data);
    } catch(error){if(live.current&&version===generation.current)setError(error instanceof Error?error.message:"Preparation failed.");}
    finally{if(live.current&&version===generation.current)setBusy(false);}
  }
  return <dialog ref={dialog} onClose={close} aria-labelledby="customer-cve-title"
    className="fixed inset-y-0 left-auto right-0 m-0 h-dvh max-h-dvh w-full max-w-2xl overflow-y-auto border-l border-zinc-700 bg-[#090909] p-6 text-zinc-100 backdrop:bg-black/70">
    <div className="flex items-start justify-between gap-4"><div><p className="text-sm text-zinc-300">{detail?.companyName ?? companyId}</p><h2 id="customer-cve-title" className="mt-1 text-2xl font-semibold">{cve}</h2></div>
      <button autoFocus className={styles.button} onClick={()=>dialog.current?.close()}>Close</button></div>
    {compareEnabled && <button className={`${styles.button} mt-4`} onClick={switchMode}>{comparison?"Return to current data":"Compare database read"}</button>}
    {comparison && <p role="note" className="mt-4 rounded-xl border border-amber-700 p-3 text-sm text-amber-100">Read-only comparison: published Defender findings only. This may not include every connector for this customer. Patch preparation and sending are unavailable in this view.</p>}
    {error && <p role="alert" className={`${styles.patchError} my-4`}>{error}</p>}
    {!detail && !error && <p role="status" className="mt-5">Loading saved customer evidence…</p>}
    {detail && <div className="mt-5 space-y-5">
      <p>{detail.findingCount.toLocaleString()} source findings · {detail.deviceCount.toLocaleString()} {comparison?"saved asset identities":"source device identities"}</p>
      <div className="text-sm text-zinc-300">
        {detail.sourceObservations.crowdstrike && <p>CrowdStrike completed import: {new Date(detail.sourceObservations.crowdstrike).toLocaleString()}.</p>}
        {detail.sourceObservations.platform && <p>Platform findings, latest source observation: {new Date(detail.sourceObservations.platform).toLocaleString()}.</p>}
        <p>Device identities are not deduplicated across connectors. Confirm current state before patching.</p>
      </div>
      {comparison && !detail.enrichment && <p className="text-sm text-zinc-300">{detail.enrichmentState==="unavailable"?"Threat enrichment storage is unavailable.":"No threat enrichment is recorded for this CVE."}</p>}
      {detail.enrichment && <div className="rounded-xl border border-zinc-800 p-3 text-sm">
        <p>CVSS {detail.enrichment.cvss_score ?? "Unknown"} · EPSS {detail.enrichment.epss_probability == null?"Unknown":`${(detail.enrichment.epss_probability*100).toFixed(2)}%`} · KEV {detail.enrichment.cisa_kev?"Listed":"Not marked in cache"}</p>
        <p className="mt-2">Threat signal: {detail.enrichment.active_exploitation ? `${detail.enrichment.active_exploitation_source ?? "Legacy source"} — ${detail.enrichment.active_exploitation_detail ?? "Detail unavailable"}` : "No positive signal recorded"}</p>
        <p className="mt-2 text-zinc-400">Shared enrichment cache updated {new Date(detail.enrichment.updated_at).toLocaleString()}; individual source freshness and retractions are not tracked.</p>
      </div>}
      <div className="max-h-64 overflow-auto rounded-xl border border-zinc-800"><table className={styles.table}><thead><tr><th>Host</th><th>Source</th><th>Severity</th><th>CVSS</th></tr></thead>
        <tbody>{detail.hosts.map((host,index)=><tr key={index}><td>{host.host}</td><td>{host.source}</td><td>{host.severity}</td><td>{host.cvss ?? "—"}</td></tr>)}</tbody></table></div>
      <p className="text-xs text-zinc-400">First {detail.hosts.length} source findings shown. {comparison?"Read-only preview; use the current-data view for patch requests.":"Prepared CSVs contain the complete eligible scope for each action, excluding already-ticketed device/CVE pairs."}</p>
      {comparison && !detail.tickets.length && <p className="text-sm text-zinc-300">No saved group requests for this customer and CVE.</p>}
      {detail.tickets.length>0 && <section><h3 className="font-medium">Saved requests for this customer and CVE</h3>
        <ul className="mt-2 space-y-1 text-sm">{detail.tickets.map(ticket=><li key={ticket.id}>{ticket.ticket_url ? <a className="text-sky-300 underline" href={ticket.ticket_url} target="_blank" rel="noopener noreferrer">Ticket #{ticket.ticket_id}</a> : "Draft request"} · {ticket.state} · {ticket.review_state}{ticket.closed?" · Closed":""}</li>)}</ul>
        {detail.moreTickets && <p>Showing the latest 100 requests. The Tickets view contains the full register.</p>}</section>}
      {!comparison && canManage && <button className={styles.primaryButton} disabled={busy} onClick={()=>void prepare()}>{busy?"Preparing saved evidence…":packet?"Refresh patch request":"Prepare patch request"}</button>}
      {!comparison && packet && <section className="space-y-4"><p className="text-sm text-zinc-300">{packet.groups.length} draft actions saved. Review each action and CSV, approve it, then use the ConnectWise form to send. These drafts are excluded from automatic creation.</p>
        {packet.groups.map(entry=><Draft key={entry.id} entry={entry} companyId={companyId}/>)}</section>}
    </div>}
  </dialog>;
}
export default function CustomerCveProvider({enabled,companyId,canManage,compareEnabled=false,children}:{enabled:boolean;companyId:string;canManage:boolean;compareEnabled?:boolean;children:ReactNode}) {
  const [cve,setCve]=useState<string|null>(null);
  if(!enabled)return children;
  return <CustomerCveContext.Provider value={companyId ? value=>setCve(value.toUpperCase()) : null}>
    {children}{companyId && cve && <Panel key={`${companyId}:${cve}`} companyId={companyId} cve={cve} canManage={canManage} compareEnabled={compareEnabled} close={()=>setCve(null)}/>}
  </CustomerCveContext.Provider>;
}
