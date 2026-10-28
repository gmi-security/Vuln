"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { RefreshCw } from "lucide-react";
import VulnShell from "./VulnShell";
import ReportingCustomer from "./ReportingCustomer";
import DefenderCustomerPanel from "./DefenderCustomerPanel";
import TopFixes from "./TopFixes";
import RiskDashboard from "./RiskDashboard";
import PatchReviewQueue from "./PatchReviewQueue";
import PatchTicketTracker from "./PatchTicketTracker";
import PatchProgress from "./PatchProgress";
import ElasticQueryDashboard from "./ElasticQueryDashboard";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { ElasticDashboard } from "@/lib/elastic-dashboard";
import type { SlaSettings } from "@/lib/types";
import styles from "./QueryDashboard.module.css";
import CustomerCveProvider from "./CustomerCveProvider";
import CustomerThreatIntelligence from "./CustomerThreatIntelligence";
import PatchPriorityWorklist from "./PatchPriorityWorklist";
import CustomerSavedSources from "./CustomerSavedSources";
import CustomerPlatformComparison from "./CustomerPlatformComparison";
import { remediationHref, remediationView, remediationViews, type RemediationView } from "@/lib/remediation-view";

function CustomerTiles({ companyId, canManage }: { companyId:string; canManage:boolean }) {
  const [dashboard,setDashboard] = useState<ElasticDashboard | null>(null);
  const [error,setError] = useState("");
  const [retry,setRetry] = useState(0);
  useEffect(()=>{
    const controller = new AbortController();
    dashboardRequest<ElasticDashboard>(`customer-tiles?companyId=${encodeURIComponent(companyId)}`, { signal: controller.signal })
      .then(data=>{if(!controller.signal.aborted){setDashboard(data);setError("");}})
      .catch(cause=>{if(!controller.signal.aborted)setError(cause instanceof Error ? cause.message : "Customer tiles are unavailable.");});
    return()=>controller.abort();
  },[companyId,retry]);
  if(error) return <div role="alert"><p>{error}</p><button className={styles.button} onClick={()=>setRetry(value=>value+1)}>Retry customer tiles</button></div>;
  if(!dashboard) return <p role="status" className="text-sm text-zinc-300">Loading this customer's saved tiles...</p>;
  return <ElasticQueryDashboard initial={{...dashboard,canManage}} companyId={companyId}/>;
}

export default function CustomerReportingPage({ initialCompanyId="", canManage, layout="reporting", initialView="overview", savedSourceReads=false, shadowCveReads=false }: {
  initialCompanyId?:string; canManage:boolean; layout?:"reporting" | "remediation"; initialView?:RemediationView; savedSourceReads?:boolean; shadowCveReads?:boolean;
}) {
  const [companyId,setCompanyId]=useState(initialCompanyId);
  const [view,setView]=useState<RemediationView>(initialView);
  const [refresh,setRefresh]=useState(0);
  const [sla,setSla]=useState<SlaSettings | null>(null);
  const remediation = layout === "remediation";
  const savedReads = remediation && savedSourceReads;
  const overview = !remediation || view === "overview";
  const prioritize = !remediation || view === "prioritize";
  const tickets = !remediation || view === "tickets";
  useEffect(()=>{
    if (!remediation) return;
    setCompanyId(initialCompanyId);
    setView(initialView);
    setRefresh(0);
  },[initialCompanyId,initialView,remediation]);
  useEffect(()=>{
    if (!remediation) return;
    function restoreLocation() {
      const params = new URL(window.location.href).searchParams;
      setCompanyId(params.get("companyId") || "");
      setView(remediationView(params.get("view")));
      setRefresh(0);
    }
    window.addEventListener("popstate",restoreLocation);
    return ()=>window.removeEventListener("popstate",restoreLocation);
  },[remediation]);
  useEffect(()=>{
    let active=true;
    fetch("/api/settings").then(response=>response.json()).then(data=>{if(active)setSla(data?.settings?.sla ?? null);}).catch(()=>{});
    return()=>{active=false;};
  },[]);
  function selectCustomer(id:string) {
    setCompanyId(id);setRefresh(0);
    if (remediation) {
      window.history.pushState(null,"",remediationHref(id,view));
      return;
    }
    const url=new URL(window.location.href);
    if(id)url.searchParams.set("companyId",id);else url.searchParams.delete("companyId");
    window.history.replaceState(null,"",url);
  }
  function selectView(next:RemediationView) {
    setView(next);
    window.history.pushState(null,"",remediationHref(companyId,next));
  }
  return <CustomerCveProvider key={remediation ? companyId : "legacy"} enabled={remediation} companyId={companyId} canManage={canManage} compareEnabled={remediation && shadowCveReads}><VulnShell variant="dashboard" eyebrow={remediation ? "Customer operations" : "Customer reporting"}
    title={remediation ? "Remediation" : "Vulnerability reporting"}
    subtitle={remediation ? "Understand exposure, prioritize fixes and track patch tickets for the selected customer." : "Select a customer to view its connected sources, findings and patch review."}
    companyId={companyId}
    actions={<div className="flex flex-wrap gap-2">
      <button className={styles.button} disabled={!companyId} onClick={()=>setRefresh(value=>value+1)}><RefreshCw size={16}/>Refresh report</button>
      {canManage && <Link className={styles.button} href="/query-tiles">Manage shared query tiles</Link>}
    </div>}>
    {remediation && <nav aria-label="Remediation views" className="flex flex-wrap gap-2">
      {remediationViews.map(value=><button key={value} type="button" aria-pressed={view === value}
        onClick={()=>selectView(value)} className={`rounded-xl border px-5 py-3 text-sm font-medium ${view === value ? "border-red-800 bg-red-950/40 text-white" : "border-zinc-800 bg-zinc-950 text-zinc-300 hover:bg-zinc-900"}`}>
        {value === "overview" ? "Overview" : value === "prioritize" ? "Prioritize" : "Tickets"}
      </button>)}
    </nav>}
    <ReportingCustomer companyId={companyId} onCompanyChange={selectCustomer} refreshToken={refresh} showReport={overview} sectionsOnly={remediation}
      setupPath={savedReads ? "customer-saved-sources?setup=1" : "reporting"}/>
    {!companyId && <p className="mt-6 text-sm text-zinc-300">Choose a customer to view its connector data. No shared customer results are shown until a customer is selected.</p>}
    {/* Remount every customer-bound child immediately. Late results and open
        exports/ticket dialogs from the previous customer cannot be reused. */}
    {companyId && <div key={`${companyId}:${refresh}:${remediation ? view : "reporting"}`} className="mt-6 space-y-6">
      {remediation && shadowCveReads && (overview || prioritize) && <CustomerPlatformComparison companyId={companyId}/>}
      {overview && <DefenderCustomerPanel companyId={companyId} hideUnconfigured/>}
      {remediation && overview && <PatchProgress companyId={companyId} view="overview"/>}
      {savedReads && (overview || prioritize) && <CustomerSavedSources companyId={companyId} showCves={prioritize}/>}
      {overview && <CustomerTiles companyId={companyId} canManage={canManage}/>}
        {prioritize && <TopFixes companyId={companyId} canManage={canManage && remediation} reviewHref={remediation ? remediationHref(companyId,"tickets") : undefined}/>}
      {remediation && prioritize && <CustomerThreatIntelligence companyId={companyId}/>}
      {!remediation && prioritize && canManage && <RiskDashboard companyId={companyId}/>}
      {remediation && prioritize && <PatchPriorityWorklist key={companyId} companyId={companyId} canManage={canManage}/>}
      {tickets && <div id="consolidation-review" className="grid items-start gap-6 2xl:grid-cols-2">
        <PatchReviewQueue companyId={companyId} sla={sla}/>
        {canManage && <PatchTicketTracker companyId={companyId} sla={sla} allowGlobalActions={false}/>}
      </div>}
      {remediation && tickets && <PatchProgress companyId={companyId} view="tickets"/>}
    </div>}

  </VulnShell></CustomerCveProvider>;
}
