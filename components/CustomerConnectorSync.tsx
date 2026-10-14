"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { RefreshCw } from "lucide-react";
import { readDashboardResponse } from "@/lib/dashboard-browser-client";
import { customerConnectorsHref } from "@/lib/remediation-view";
import type { CustomerSyncStatus, SyncState } from "@/lib/customer-connector-sync-model";
import styles from "./QueryDashboard.module.css";

const states: Record<SyncState,string> = {idle:"No sync recorded",queued:"Queued",running:"Syncing",succeeded:"Succeeded",failed:"Failed",interrupted:"Interrupted",unavailable:"Not available"};
function date(value: string | null) { return value ? new Date(value).toLocaleString() : "Not recorded"; }
export default function CustomerConnectorSync({companyId,refresh}:{companyId:string;refresh:number}) {
  const [data,setData] = useState<CustomerSyncStatus | null>(null), [error,setError] = useState("");
  const [notice,setNotice] = useState(""), [actionError,setActionError] = useState(""), [requesting,setRequesting] = useState<string | null>(null), [version,setVersion] = useState(0);
  const lock = useRef(false), mounted = useRef(true);
  const [pending,setPending] = useState<{id:string;at:number} | null>(null);
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
  useEffect(()=>{
    const controller = new AbortController(); let active = true, timer: ReturnType<typeof setTimeout>;
    async function read() {
      if (document.visibilityState !== "visible") { timer=setTimeout(read,60_000); return; }
      let delay = 60_000;
      try {
        const response = await fetch(`/api/elastic-dashboard/customer-sync?companyId=${encodeURIComponent(companyId)}`,{
          cache:"no-store",signal:AbortSignal.any([controller.signal,AbortSignal.timeout(20_000)]),headers:{Accept:"application/json"},
        });
        const result = await readDashboardResponse<CustomerSyncStatus>(response);
        if (result.companyId !== companyId || !Array.isArray(result.rows)) throw new Error("Sync status did not match the selected customer.");
        if (!active) return;
        setData(result); setError("");
        if (pending) {
          const row = result.rows.find(row=>row.id===pending.id);
          if ((row && (["running","queued"].includes(row.state) || new Date(row.lastAttemptAt ?? 0).getTime() >= pending.at)) || Date.now()-pending.at>30_000) setPending(null);
          delay = 5_000;
        }
        if (result.rows.some(row=>["running","queued"].includes(row.state))) delay=10_000;
      } catch(cause) {
        if (active) setError(cause instanceof Error ? cause.message : "Sync status is unavailable.");
      } finally {
        if (active) timer=setTimeout(read,delay);
      }
    }
    void read();
    return ()=>{active=false;controller.abort();clearTimeout(timer);};
  },[companyId,refresh,version,pending]);
  async function start(id: string) {
    if(lock.current) return;
    lock.current=true;setRequesting(id);setNotice("");setActionError("");
    const at=Date.now();
    try {
      const response = await fetch(`/api/elastic-dashboard/customer-sync?companyId=${encodeURIComponent(companyId)}`,{
        method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},body:JSON.stringify({id}),signal:AbortSignal.timeout(30_000),
      });
      await readDashboardResponse(response);
      if(mounted.current){setPending({id,at});setNotice("Sync requested. Results will update here as the job runs.");}
    } catch(cause) {
      if(mounted.current) setActionError(cause instanceof Error ? `${cause.message} Check status before retrying.` : "Could not confirm the request. Check status before retrying.");
    } finally {
      lock.current=false;
      if(mounted.current){setRequesting(null);setVersion(v=>v+1);}
    }
  }
  return <section aria-label="Sync status" className="rounded-2xl border border-zinc-700 bg-[#0c0c0c] p-5">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h3 className="text-lg font-semibold text-white">Sync status</h3><p className="mt-1 text-sm text-zinc-300">Last successful imports and saved-query refreshes for this customer. Times use your time zone.</p></div>
      <button className={styles.button} onClick={()=>setVersion(v=>v+1)} disabled={!!requesting}><RefreshCw size={14}/>Check sync status</button>
    </div>
    {data?.schedulerPaused && <p className="mt-3 rounded-lg border border-amber-800/60 bg-amber-950/20 p-3 text-sm text-amber-100">General scheduled processing is paused. Manual syncs remain available; starting one does not turn the scheduler back on.</p>}
    {error && <p role="alert" className="mt-3 text-sm text-red-200">{error}{data ? " Previously loaded status is shown." : ""}</p>}
    {actionError && <p role="alert" className="mt-3 text-sm text-red-200">{actionError}</p>}
    {notice && <p role="status" className="mt-3 text-sm text-zinc-200">{notice}</p>}
    {!data && !error && <p className="mt-4 text-sm text-zinc-300">Loading sync status…</p>}
    {data && !data.rows.length && <p className="mt-4 text-sm text-zinc-300">No sync operations are recorded for this customer.</p>}
    {!!data?.rows.length && <div className="mt-4 max-h-[32rem] overflow-auto rounded-xl border border-zinc-800">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="sticky top-0 bg-[#151515] text-zinc-200"><tr><th className="p-3">Source / operation</th><th className="p-3">Last successful sync</th><th className="p-3">Status</th><th className="p-3">Action</th></tr></thead>
        <tbody>{data.rows.map(row=><tr key={row.id} className="border-t border-zinc-800 align-top">
          <td className="p-3"><div className="font-medium text-zinc-100">{row.label}</div><p className="mt-1 max-w-lg text-xs leading-relaxed text-zinc-300">{row.detail}</p>{row.scope === "shared" && <span className="mt-2 inline-block rounded border border-amber-800 px-2 py-0.5 text-xs text-amber-100">Shared operation</span>}</td>
          <td className="whitespace-nowrap p-3 text-zinc-200">{date(row.lastSuccessAt)}{row.lastAttemptAt && <div className="mt-1 text-xs text-zinc-300">Last attempt: {date(row.lastAttemptAt)}</div>}</td>
          <td className={`p-3 ${row.state === "failed" || row.state === "interrupted" ? "text-red-200" : row.state === "running" || row.state === "queued" ? "text-sky-200" : row.state === "succeeded" ? "text-emerald-200" : "text-zinc-300"}`}>{states[row.state]}</td>
          <td className="p-3">{row.action === "shared" ? <Link className={styles.button} href={customerConnectorsHref(companyId,true)}>Shared tools</Link> : row.action && <button className={styles.button}
            aria-label={`${row.action === "refresh" ? "Refresh" : "Sync"} ${row.label}`} title={!row.canSync ? row.detail : undefined}
            disabled={!row.canSync || !!error || !!requesting || pending?.id===row.id} onClick={()=>void start(row.id)}>
              <RefreshCw size={14} className={requesting===row.id || pending?.id===row.id || row.state === "running" ? "animate-spin" : ""}/>
              {requesting===row.id ? "Starting…" : pending?.id===row.id ? "Requested" : row.state === "running" ? "Syncing…" : ["queued","interrupted"].includes(row.state) ? row.action === "refresh" ? "Resume refresh" : "Resume sync" : row.action === "refresh" ? "Refresh query" : "Sync now"}
            </button>}</td>
        </tr>)}</tbody>
      </table>
    </div>}
  </section>;
}
