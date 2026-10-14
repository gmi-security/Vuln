"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { RefreshCw } from "lucide-react";
import VulnShell from "./VulnShell";
import ReportingCustomer from "./ReportingCustomer";
import { readDashboardResponse } from "@/lib/dashboard-browser-client";
import { customerConnectorsHref } from "@/lib/remediation-view";
import type { CustomerConnectorStatus } from "@/lib/customer-connector-status";
import CustomerConnectorSync from "./CustomerConnectorSync";
import styles from "./QueryDashboard.module.css";

const names: Record<string, string> = { appsec: "AppSec", defender: "Microsoft Defender", crowdstrike: "CrowdStrike", elastic: "Elasticsearch",
  misp: "MISP", opencti: "OpenCTI", intelowl: "IntelOwl", spiderfoot: "SpiderFoot", automate: "ConnectWise Automate", tidal: "Tidal", intune: "Intune" };

function Status({ companyId, refresh }: { companyId: string; refresh: number }) {
  const [result, setResult] = useState<CustomerConnectorStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController(); let active = true;
    setLoading(true); setError("");
    fetch(`/api/elastic-dashboard/customer-connectors?companyId=${encodeURIComponent(companyId)}`, {
      cache: "no-store", signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20000)]), headers: { Accept: "application/json" },
    }).then(response => readDashboardResponse<CustomerConnectorStatus>(response)).then(data => {
      if (data.companyId !== companyId || !Array.isArray(data.items)) throw new Error("The response did not match the selected customer.");
      if (active) setResult(data);
    }).catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Connector status is unavailable."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [companyId, refresh]);
  const data = result?.companyId === companyId ? result : null;
  const providers = [...new Set(data?.items.map(item => item.provider) ?? [])];
  return <section aria-label="Customer connector status" aria-busy={loading} className="space-y-4">
    {error && <div role="alert" className="rounded-xl border border-red-900 bg-red-950/20 p-4 text-sm text-red-200">
      {error}{data && <p className="mt-2">Previously loaded configuration is shown below. It may be out of date.</p>}
    </div>}
    {loading && <p role="status" className="text-sm text-zinc-300">Loading saved connector information…</p>}
    {data && <>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h2 className="text-xl font-semibold text-white">{data.companyName}</h2>
          <p className="mt-1 text-sm text-zinc-300">{data.items.length} configuration and review {data.items.length === 1 ? "record" : "records"} · {providers.length} source {providers.length === 1 ? "type" : "types"}</p></div>
        <p className="text-xs text-zinc-300">Configuration checked {new Date(data.checkedAt).toLocaleString()}</p>
      </div>
      {data.sourceSelection && <section aria-label="Endpoint source selection" className="rounded-xl border border-zinc-800 bg-[#090909] p-4">
        <h3 className="font-medium text-white">Endpoint source selection</h3>
        <p className="mt-1 text-sm text-zinc-200">{data.sourceSelection.readiness}</p>
        {data.sourceSelection.state === "reviewed" && <p className="mt-2 text-sm text-zinc-300">
          {data.sourceSelection.primaryCount} primary sources and {data.sourceSelection.mirrorCount} declared mirrors. A mirror does not contribute a second findings total to the proposed model.
        </p>}
        <p className="mt-2 text-xs text-zinc-300">Selection review is separate from import approval and reporting activation.</p>
      </section>}
      <CustomerConnectorSync key={companyId} companyId={companyId} refresh={refresh}/>
      {!data.registryAvailable && <p className="rounded-xl border border-amber-900/70 bg-amber-950/20 p-4 text-sm text-amber-100">
        Registry review has not been initialized. Existing customer configuration is shown; source routing remains unchanged.
      </p>}
      {!data.items.length && <p className="rounded-xl border border-zinc-800 p-5 text-zinc-300">No customer-specific connector mapping or proposal is recorded. This does not mean the customer has no historical findings.</p>}
      <div className={`grid items-start gap-4 ${providers.length > 1 ? "xl:grid-cols-2" : ""}`}>
        {providers.map(provider => <article key={provider} className="min-w-0 rounded-2xl border border-zinc-800 bg-[#090909] p-5">
          <h3 className="text-lg font-semibold text-white">{names[provider] ?? provider}</h3>
          <div className="mt-4 max-h-[32rem] space-y-4 overflow-y-auto pr-1">
            {data.items.filter(item => item.provider === provider).map(item => <div key={item.id} className="border-t border-zinc-800 pt-4">
              <div className="flex flex-wrap justify-between gap-2"><h4 className="text-sm font-medium text-zinc-100">{item.evidence}</h4>
                <span className={`rounded-full border px-2 py-1 text-xs ${item.review.toLowerCase().includes("needs review") ? "border-amber-800 text-amber-200" : "border-zinc-700 text-zinc-200"}`}>{item.review}</span></div>
              <p className="mt-2 text-sm text-zinc-200">{item.configuration}</p>
              <p className="mt-1 text-sm text-zinc-300">{item.scope}</p>
              {item.data && <details className="mt-3 text-sm text-zinc-300"><summary className="cursor-pointer text-zinc-100">How this source is used</summary>
                <p className="mt-2">{item.data.storage}</p><p className="mt-1">{item.data.lifecycle}</p><p className="mt-2">{item.data.routing}</p></details>}
              {item.reviewedAt && <p className="mt-2 text-xs text-zinc-300">Prior review recorded {new Date(item.reviewedAt).toLocaleString()}</p>}
              {!!item.reasons.length && <details className="mt-3 text-sm text-zinc-300"><summary className="cursor-pointer text-red-200">Review details ({item.reasons.length})</summary>
                <ul className="mt-2 list-disc space-y-2 pl-5">{item.reasons.map((reason, i) => <li key={i}>{reason}</li>)}</ul></details>}
            </div>)}
          </div>
        </article>)}
      </div>
    </>}
  </section>;
}

export default function CustomerConnectorsPage({ initialCompanyId = "" }: { initialCompanyId?: string }) {
  const [companyId, setCompanyId] = useState(initialCompanyId), [refresh, setRefresh] = useState(0);
  useEffect(() => { setCompanyId(initialCompanyId); setRefresh(0); }, [initialCompanyId]);
  useEffect(() => {
    const restore = () => { setCompanyId(new URL(window.location.href).searchParams.get("companyId") || ""); setRefresh(0); };
    window.addEventListener("popstate", restore); return () => window.removeEventListener("popstate", restore);
  }, []);
  function selectCustomer(id: string) { setCompanyId(id); setRefresh(0); window.history.pushState(null, "", customerConnectorsHref(id)); }
  return <VulnShell variant="dashboard" eyebrow="Customer operations" title="Customer connectors"
    subtitle="Review source configuration and proposed assignments for the selected customer."
    companyId={companyId}
    actions={<div className="flex flex-wrap gap-2"><button className={styles.button} onClick={() => setRefresh(n => n + 1)}><RefreshCw size={16}/>Refresh status</button>
      <Link className={styles.button} href={customerConnectorsHref(companyId, true)}>Shared connector tools</Link></div>}>
    <ReportingCustomer key={`selector-${refresh}`} companyId={companyId} onCompanyChange={selectCustomer} refreshToken={refresh} showReport={false} setupPath="customer-connectors?setup=1"/>
    <p className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 text-sm leading-relaxed text-zinc-300">
      Sync status shows recorded imports and query refreshes. Use Sync now to request an import, or Refresh query to update a saved tile. Configuration review below is separate: reviewing an assignment does not enable it or test live access. Shared tools may affect multiple customers.
    </p>
    {companyId ? <Status key={companyId} companyId={companyId} refresh={refresh}/> : <p className="text-sm text-zinc-300">Choose a customer to see its source configuration. Shared connections are not automatically assigned to every customer.</p>}
  </VulnShell>;
}
