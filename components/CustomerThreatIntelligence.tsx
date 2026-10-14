"use client";
import { useEffect,useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { customerThreatIntelligence } from "@/lib/customer-threat-intelligence";
import CveText from "./CveText";
import styles from "./QueryDashboard.module.css";
type Data=Awaited<ReturnType<typeof customerThreatIntelligence>>;
export default function CustomerThreatIntelligence({companyId}:{companyId:string}) {
  const [data,setData]=useState<Data|null>(null),[error,setError]=useState(""),[retry,setRetry]=useState(0);
  useEffect(()=>{let active=true;setData(previous=>previous?.companyId===companyId?previous:null);setError("");
    dashboardRequest<Data>(`customer-threat-intelligence?companyId=${encodeURIComponent(companyId)}`).then(value=>{if(active && value.companyId===companyId)setData(value);}).catch(error=>{if(active)setError(error.message);});
    return()=>{active=false;};},[companyId,retry]);
  return <section aria-label="Threat Intelligence" className="rounded-2xl border border-zinc-800 bg-[#090909] p-5">
    <div className="flex items-center justify-between gap-3"><h2 className="text-xl font-semibold">Threat Intelligence</h2><button className={styles.button} onClick={()=>setRetry(value=>value+1)}>Refresh saved evidence</button></div>
    <p className="my-3 text-sm text-zinc-300">Recorded enrichment for this customer’s open CVEs: CISA KEV, EPSS and signals from configured MISP/OpenCTI/IntelOwl sources. Click a CVE to review its devices and prepare a request.</p>
    <p className="mb-4 text-xs text-zinc-400">Legacy signals are retained evidence, not confirmation of current exploitation. The cache has one shared update time, may retain older positive flags and does not track each source’s latest check or retraction. No recorded signal does not establish that a source checked and found nothing.</p>
    {error && <p role="alert" className={styles.patchError}>{error}{data ? " Previously loaded evidence remains below with its recorded timestamps." : ""}</p>}
    {!data && !error && <p role="status">Loading saved threat intelligence…</p>}
    {data && !data.available && <p>Enrichment storage is not available for this deployment.</p>}
    {data?.available && <><p className="mb-3 text-sm">Showing {data.rows.length} of {data.total} CVEs with recorded enrichment.</p>
      {!data.rows.length && <p>No matching enrichment is available for this customer’s open findings.</p>}
      <div className="max-h-96 overflow-auto"><table className={styles.table}><thead><tr><th>CVE</th><th>KEV</th><th>EPSS</th><th>Recorded signal</th><th>Cache updated</th></tr></thead>
        <tbody>{data.rows.map(row=><tr key={row.cve}><td><CveText text={row.cve}/></td><td>{row.cisa_kev?"Listed":"Not marked"}</td><td>{row.epss_probability==null?"Unknown":`${(row.epss_probability*100).toFixed(2)}%`}</td><td>{row.active_exploitation ? `${row.active_exploitation_source ?? "Legacy source"}: ${row.active_exploitation_detail ?? "Detail unavailable"}` : "No positive signal recorded"}</td><td>{new Date(row.updated_at).toLocaleString()}</td></tr>)}</tbody></table></div></>}
  </section>;
}
