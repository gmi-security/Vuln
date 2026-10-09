"use client";

import {useEffect,useId,useState} from "react";
import {readDashboardResponse} from "@/lib/dashboard-browser-client";
import {useCustomerCve} from "./customer-cve-context";
import styles from "./QueryDashboard.module.css";

type Row={id?:string;cve:string|null;asset?:string|null;severity:string;realRisk:number|null;cvss:number|null;status?:string;affectedDevices?:number;findings?:number};
type Result={state:"available"|"unpublished";companyId:string;scope:string;projectionId?:string;
  publication?:{revision:number;publishedAt:string};summary?:{openRemediation:number;uniqueOpenCves:number;affectedDeviceIds:number};
  page?:{total:number;rows:Row[];nextCursor:string|null}|null};
type View="findings"|"cves";
const statuses=["open","all","Open","In Remediation","Risk Accepted","False Positive","Resolved"];

export default function CustomerPlatformComparison({companyId}:{companyId:string}) {
  const [opened,setOpened]=useState(false),[view,setView]=useState<View>("findings"),[status,setStatus]=useState("open");
  const [cursors,setCursors]=useState<(string|null)[]>([null]),[attempt,setAttempt]=useState(0);
  const [result,setResult]=useState<Result|null>(null),[error,setError]=useState(""),[restart,setRestart]=useState(false);
  const openCve=useCustomerCve(),regionId=useId(),filterId=useId();
  const cursor=cursors[cursors.length-1];
  function clear(){setResult(null);setError("");setRestart(false);}
  function reset(){clear();setCursors([null]);setAttempt(value=>value+1);}
  useEffect(()=>{
    if(!opened)return;
    let active=true;
    const controller=new AbortController();
    setResult(null);setError("");setRestart(false);
    const params=new URLSearchParams({companyId,view,status,limit:"50"});
    if(cursor)params.set("cursor",cursor);
    async function load(){
      let conflict=false;
      try{
        const response=await fetch(`/api/elastic-dashboard/customer-platform-comparison?${params}`,{
          cache:"no-store",signal:AbortSignal.any([controller.signal,AbortSignal.timeout(20000)])});
        conflict=response.status===409;
        const data=await readDashboardResponse<Result>(response);
        if(!active)return;
        if(data.companyId!==companyId||data.scope!=="published-defender-cohort"||!["available","unpublished"].includes(data.state))throw new Error("Comparison response did not match the selected customer and view.");
        if(data.state==="available"&&(!data.projectionId||!data.publication||!data.summary||!data.page||!Array.isArray(data.page.rows)||data.page.rows.length>50))throw new Error("Comparison returned an incomplete page.");
        setResult(data);
      }catch(cause){if(active){setError(cause instanceof Error?cause.message:"Comparison unavailable.");setRestart(conflict&&!!cursor);}}
    }
    void load();
    return()=>{active=false;controller.abort();};
  },[companyId,opened,view,status,cursor,attempt]);
  function cveCell(cve:string|null){return cve&&/^CVE-\d{4}-\d+$/i.test(cve)&&openCve&&result?.projectionId
    ? <button className="text-sky-300 underline hover:text-sky-100" onClick={()=>openCve(cve,{comparison:true,projectionId:result.projectionId!})}>{cve}</button>
    : cve||"No CVE recorded";}
  return <section className="min-w-0 rounded-xl border border-zinc-700 bg-zinc-950 p-4">
    <button className={styles.button} aria-expanded={opened} aria-controls={regionId} onClick={()=>{clear();setCursors([null]);setOpened(value=>!value);}}>{opened?"Close published comparison":"Compare published data"}</button>
    {opened&&<div id={regionId} role="region" aria-label="Published data comparison" className="mt-4 min-w-0 space-y-4">
      <p className="text-sm text-amber-100">Read-only comparison of published Defender findings for this customer. Other connectors are not included. Counts describe saved platform findings, not live source totals.</p>
      <div className="flex flex-wrap items-center gap-3">
        {(["findings","cves"] as const).map(value=><button key={value} className={`${styles.button} ${view===value?"!border-red-800 !bg-red-950/40":""}`} aria-pressed={view===value} onClick={()=>{clear();setView(value);setStatus("open");setCursors([null]);setAttempt(n=>n+1);}}>{value==="findings"?"Findings":"CVEs"}</button>)}
        {view==="findings"&&<><label htmlFor={filterId} className="text-sm">Workflow</label><select id={filterId} className="max-w-full rounded border border-zinc-700 bg-zinc-900 p-2 text-zinc-100" value={status} onChange={event=>{clear();setStatus(event.target.value);setCursors([null]);setAttempt(n=>n+1);}}>{statuses.map(value=><option key={value} value={value}>{value==="open"?"Open remediation scope":value==="all"?"All statuses":value}</option>)}</select></>}
        <button className={styles.button} onClick={reset}>Refresh comparison</button>
      </div>
      {error?<div role="alert"><p>{error}</p><button className={`${styles.button} mt-2`} onClick={reset}>{restart?"Restart from first page":"Retry comparison"}</button></div>
        :!result?<p role="status">Loading published comparison...</p>
        :result.state==="unpublished"?<p>No verified publication is available for this customer. This does not mean there are zero findings.</p>
        :<>
          <p className="text-sm text-zinc-300">Publication revision {result.publication!.revision} · Published {new Date(result.publication!.publishedAt).toLocaleString()}</p>
          <dl className="grid gap-4 sm:grid-cols-3">{[["Open remediation findings",result.summary!.openRemediation],["Unique open CVEs",result.summary!.uniqueOpenCves],["Affected device IDs",result.summary!.affectedDeviceIds]].map(([label,value])=><div key={label}><dt className="text-sm text-zinc-300">{label}</dt><dd className="text-xl font-semibold text-zinc-100">{value.toLocaleString()}</dd></div>)}</dl>
          <p className="text-xs text-zinc-300">Summary counts cover the published open-remediation scope, regardless of the list filter. Affected device IDs are not an inventory or scan-coverage count.</p>
          <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800" tabIndex={0} role="region" aria-label="Comparison rows">
            <table className={`${styles.table} min-w-[640px]`}><thead className="sticky top-0 bg-zinc-950"><tr><th>CVE</th>{view==="findings"?<th>Asset</th>:<><th>Affected devices</th><th>Findings</th></>}<th>Severity</th><th>Saved risk</th><th>CVSS</th>{view==="findings"&&<th>Status</th>}</tr></thead>
              <tbody>{result.page!.rows.map((row,index)=><tr key={row.id||row.cve||index}><td>{cveCell(row.cve)}</td>{view==="findings"?<td>{row.asset||"Unknown asset"}</td>:<><td>{row.affectedDevices?.toLocaleString()}</td><td>{row.findings?.toLocaleString()}</td></>}<td>{row.severity}</td><td>{row.realRisk??"Unknown"}</td><td>{row.cvss??"Unknown"}</td>{view==="findings"&&<td>{row.status}</td>}</tr>)}</tbody>
            </table>
            {!result.page!.rows.length&&<p className="p-4">No records match this list in the verified publication.</p>}
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm"><button className={styles.button} disabled={cursors.length===1} onClick={()=>{clear();setCursors(values=>values.slice(0,-1));}}>Previous page</button><span>Page {cursors.length} · {result.page!.total.toLocaleString()} matching records</span><button className={styles.button} disabled={!result.page!.nextCursor} onClick={()=>{const next=result.page!.nextCursor;if(next){clear();setCursors(values=>[...values,next]);}}}>Next page</button></div>
        </>}
    </div>}
  </section>;
}
