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
import ElasticQueryDashboard from "./ElasticQueryDashboard";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { ElasticDashboard } from "@/lib/elastic-dashboard";
import type { SlaSettings } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

function CustomerTiles({ companyId, canManage }: { companyId:string; canManage:boolean }) {
  const [dashboard,setDashboard] = useState<ElasticDashboard | null>(null);
  const [error,setError] = useState("");
  const [retry,setRetry] = useState(0);
  useEffect(()=>{
    let active=true;
    dashboardRequest<ElasticDashboard>(`customer-tiles?companyId=${encodeURIComponent(companyId)}`)
      .then(data=>{if(active){setDashboard(data);setError("");}})
      .catch(cause=>{if(active)setError(cause instanceof Error ? cause.message : "Customer tiles are unavailable.");});
    return()=>{active=false;};
  },[companyId,retry]);
  if(error) return <div role="alert"><p>{error}</p><button className={styles.button} onClick={()=>setRetry(value=>value+1)}>Retry customer tiles</button></div>;
  if(!dashboard) return <p role="status" className="text-sm text-zinc-300">Loading this customer's saved tiles...</p>;
  return <ElasticQueryDashboard initial={{...dashboard,canManage}} companyId={companyId}/>;
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
