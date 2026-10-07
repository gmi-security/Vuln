"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Download, RefreshCw } from "lucide-react";
import VulnShell from "./VulnShell";
import ReportingCustomer from "./ReportingCustomer";
import DefenderCustomerPanel from "./DefenderCustomerPanel";
import TopFixes from "./TopFixes";
import RiskDashboard from "./RiskDashboard";
import PatchReviewQueue from "./PatchReviewQueue";
import PatchTicketTracker from "./PatchTicketTracker";
import Results from "./QueryDashboardResults";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { dashboardCsv } from "@/lib/dashboard-csv";
import type { ElasticDashboard, DashboardQuery } from "@/lib/elastic-dashboard";
import type { SlaSettings } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

function download(query: DashboardQuery, companyId: string) {
  if (!query.result) return;
  const url = URL.createObjectURL(new Blob([dashboardCsv(query.result)],{type:"text/csv;charset=utf-8"}));
  const link = document.createElement("a");link.href=url;link.download=`${companyId}-${query.id}.csv`;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

function CustomerTiles({ companyId, canManage }: { companyId:string; canManage:boolean }) {
  const [dashboard,setDashboard] = useState<ElasticDashboard | null>(null);
  const [error,setError] = useState("");
  const [message,setMessage] = useState("");
  const [busy,setBusy] = useState(false);
  const [refresh,setRefresh] = useState(0);
  const path = `customer-tiles?companyId=${encodeURIComponent(companyId)}`;
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const data=await dashboardRequest<ElasticDashboard>(path);
        if (!active) return;
        if (!data.storageReady) throw new Error("Saved tile storage is unavailable. Previously loaded results for this customer are retained.");
        setDashboard(data);setError("");
        // Poll cached results only, without executing source queries on reads.
        if(data.queries.length) timer=setTimeout(()=>void load(),15_000);
      } catch(cause) {
        if(active) {setError(cause instanceof Error ? cause.message : "Customer tiles are unavailable.");timer=setTimeout(()=>void load(),30_000);}
      }
    }
    void load();return()=>{active=false;clearTimeout(timer);};
  },[path,refresh]);
  async function refreshTiles() {
    setBusy(true);setError("");setMessage("");
    try {
      const result=await dashboardRequest<{queued:boolean;count:number}>(path,{method:"POST"});
      setMessage(result.queued ? "Refresh requested for this customer's assigned tiles." : "No assigned source tiles to refresh.");
      setRefresh(value=>value+1);
    } catch(cause) {setError(cause instanceof Error ? cause.message : "Refresh could not be requested.");}
    finally {setBusy(false);}
  }
  if (!dashboard && !error) return <p role="status" className="text-sm text-zinc-300">Loading this customer's saved tiles…</p>;
  if (dashboard && !dashboard.queries.length && !error) return null;
  return <section aria-label="Customer connector tiles" className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="text-xl font-semibold text-white">Connector tiles</h2><p className="text-sm text-zinc-300">Saved results assigned to this customer. Each source retains its own measurement and refresh time.</p></div>
      {canManage && !!dashboard?.queries.length && <button className={styles.button} disabled={busy} onClick={()=>void refreshTiles()}><RefreshCw size={16}/>Refresh connector tiles</button>}
    </div>
    {error && <p role="alert" className="text-sm text-amber-300">{error}</p>}
    {message && <p role="status" className="text-sm text-zinc-300">{message}</p>}
    <div className={styles.board}>{dashboard?.queries.map(query=><section key={query.id} className={`${styles.tile} ${query.display === "table" ? styles.wide : ""}`} aria-label={query.title}>
      <header className={styles.tileHeader}><div className={styles.tileHeading}><h2>{query.title}</h2><p className="text-xs text-zinc-300">{query.source === "crowdstrike" ? "CrowdStrike" : "Elasticsearch"}</p></div>
        {query.result && <button className={styles.button} onClick={()=>download(query,companyId)} aria-label={`Download ${query.title} CSV`}><Download size={14}/>CSV</button>}
      </header>
      <div className={styles.tileContent}>
        {query.error && <p className="mb-4 text-sm text-amber-300">{query.error}{query.result ? " Showing the last successful result." : " No successful result yet."}</p>}
        {query.result ? <Results result={query.result} display={query.display} chart={query.chart} companyId={companyId} preparePatch={canManage && query.source === "crowdstrike" && dashboard.crowdstrike?.connected}/> : !query.error && <p className="text-sm text-zinc-300">No saved result yet. Request a refresh to load this tile.</p>}
        {(query.description || query.result?.note) && <details className={styles.resultDetails}><summary>Result details</summary>{query.description && <p>{query.description}</p>}{query.result?.note && <p>{query.result.note}</p>}</details>}
      </div>
      <footer className={styles.tileFooter}>{query.refreshedAt ? `Updated ${new Date(query.refreshedAt).toLocaleString()}` : "No successful result yet"}</footer>
    </section>)}</div>
  </section>;
}

export default function CustomerReportingPage({ initialCompanyId="", canManage }: { initialCompanyId?:string; canManage:boolean }) {
  const [companyId,setCompanyId]=useState(initialCompanyId);
  const [refresh,setRefresh]=useState(0);
  const [sla,setSla]=useState<SlaSettings | null>(null);
  useEffect(()=>{
    let active=true;
    fetch("/api/settings").then(response=>response.json()).then(data=>{if(active)setSla(data?.settings?.sla ?? null);}).catch(()=>{});
    return()=>{active=false;};
  },[]);
  function selectCustomer(id:string) {
    setCompanyId(id);setRefresh(0);
    const url=new URL(window.location.href);
    if(id)url.searchParams.set("companyId",id);else url.searchParams.delete("companyId");
    window.history.replaceState(null,"",url);
  }
  return <VulnShell variant="dashboard" eyebrow="Customer reporting" title="Vulnerability reporting"
    subtitle="Select a customer to view its connected sources, findings and patch review."
    actions={<div className="flex flex-wrap gap-2">
      <button className={styles.button} disabled={!companyId} onClick={()=>setRefresh(value=>value+1)}><RefreshCw size={16}/>Refresh report</button>
      {canManage && <Link className={styles.button} href="/query-tiles">Manage shared query tiles</Link>}
    </div>}>
    <ReportingCustomer companyId={companyId} onCompanyChange={selectCustomer} refreshToken={refresh}/>
    {!companyId && <p className="mt-6 text-sm text-zinc-300">Choose a customer to view its connector data. No shared customer results are shown until a customer is selected.</p>}
    {/* Remount every customer-bound child immediately. Late results and open
        exports/ticket dialogs from the previous customer cannot be reused. */}
    {companyId && <div key={`${companyId}:${refresh}`} className="mt-6 space-y-6">
      <DefenderCustomerPanel companyId={companyId} hideUnconfigured/>
      <CustomerTiles companyId={companyId} canManage={canManage}/>
      <TopFixes companyId={companyId}/>
      {canManage && <RiskDashboard companyId={companyId}/>}
      <div id="consolidation-review" className="grid items-start gap-6 2xl:grid-cols-2">
        <PatchReviewQueue companyId={companyId} sla={sla}/>
        {canManage && <PatchTicketTracker companyId={companyId} sla={sla} allowGlobalActions={false}/>}
      </div>
    </div>}
  </VulnShell>;
}
