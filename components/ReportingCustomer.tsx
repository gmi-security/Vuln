"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import CustomerScanViews from "@/components/CustomerScanViews";
import type { CustomerInsights } from "@/lib/reporting-insights";
import type { ExecReport } from "@/lib/store";
import { selectClass } from "@/components/ui";

type Setup = { companies: { id: string; name: string }[] };
type Customer = { report: ExecReport; sources: { name: string; open: number }[]; insights: CustomerInsights };
const number = (value: number) => value.toLocaleString();

export default function ReportingCustomer({ companyId, onCompanyChange, onCustomerReady, refreshToken }: { companyId: string; onCompanyChange: (companyId: string) => void; onCustomerReady: (ready: boolean) => void; refreshToken: number }) {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    dashboardRequest<Setup>("reporting").then(data => { if (active) setSetup(data); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Reporting is unavailable."); });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!companyId) { setCustomer(null); onCustomerReady(false); return; }
    let active = true;
    onCustomerReady(false);
    setCustomer(null); setLoading(true); setError("");
    dashboardRequest<Customer>(`reporting?companyId=${encodeURIComponent(companyId)}`)
      .then(data => { if (active) { setCustomer(data); onCustomerReady(true); } })
      .catch(cause => { if (active) { onCustomerReady(false); setError(cause instanceof Error ? cause.message : "Customer report is unavailable."); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [companyId, refreshToken, onCustomerReady]);

  const report = customer?.report.company.id === companyId ? customer.report : null;
  return <><section aria-label="Customer report" className="rounded-2xl border border-zinc-800 bg-[#090909] p-5 sm:p-7">
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-zinc-800 pb-5">
      <div><p className="text-xs uppercase tracking-[0.25em] text-red-500">Customer reporting</p>
        <h2 className="mt-2 text-2xl font-semibold text-white">Customer report</h2>
        <p className="mt-2 max-w-2xl text-sm text-zinc-400">Select an app customer to see its findings across all connected scanners.</p></div>
      {report && <Link href={`/report/${encodeURIComponent(report.company.id)}`} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-100 hover:bg-zinc-800">Open full report</Link>}
    </div>
    {!setup && !error && <p role="status" className="text-sm text-zinc-400">Loading customer reporting…</p>}
    {setup && <label className="block max-w-xl text-sm text-zinc-200">Customer
      <select className={`${selectClass} mt-2 block w-full`} value={companyId} onChange={event => onCompanyChange(event.target.value)}>
        <option value="">Choose a customer</option>
        {setup.companies.map(company => <option key={company.id} value={company.id}>{company.name} ({company.id})</option>)}
      </select>
    </label>}
    {error && <p role="alert" className="mt-4 text-sm text-red-300">{error}</p>}
    {loading && <p role="status" className="mt-5 text-sm text-zinc-400">Loading this customer’s report…</p>}
    {report && customer && <div className="mt-6 space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-xl font-medium text-white">{report.company.name}</h3>
        <p className="mt-1 text-xs text-zinc-500">{report.company.id} · Updated {new Date(report.generatedAt).toLocaleString()}</p></div></div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Open findings", number(report.findings.open)], ["Critical open", number(report.findings.critical)],
          ["Known exploited", number(report.findings.kevOpen)], ["Exposure score", number(report.posture.exposureScore)],
        ].map(([label, value]) => <div key={label} className="rounded-xl border border-zinc-800 bg-black p-4"><p className="text-xs text-zinc-400">{label}</p><p className="mt-2 text-3xl font-semibold tabular-nums text-white">{value}</p></div>)}
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="rounded-xl border border-zinc-800 p-5"><h4 className="font-medium text-white">Next priorities</h4>
          {report.topRisks.length ? <ul className="mt-3 divide-y divide-zinc-800">{report.topRisks.map((risk, index) => <li key={`${risk.cve}-${index}`} className="flex items-start justify-between gap-4 py-3 text-sm"><span className="min-w-0"><span className="block font-medium text-zinc-100">{risk.cve}</span><span className="block truncate text-zinc-400">{risk.title}</span></span><span className="shrink-0 tabular-nums text-red-300">{risk.realRisk}</span></li>)}</ul> : <p className="mt-3 text-sm text-zinc-400">No open priorities.</p>}
        </div>
        <div className="rounded-xl border border-zinc-800 p-5"><h4 className="font-medium text-white">Scanner coverage</h4>
          <p className="mt-2 text-xs text-zinc-500">Open findings observed by each source. A finding seen by multiple scanners appears under each source.</p>
          {customer.sources.length ? <ul className="mt-3 divide-y divide-zinc-800">{customer.sources.map(source => <li key={source.name} className="flex justify-between gap-3 py-3 text-sm"><span className="capitalize text-zinc-200">{source.name}</span><span className="tabular-nums text-white">{number(source.open)}</span></li>)}</ul> : <p className="mt-3 text-sm text-zinc-400">No open findings from a scanner.</p>}
        </div>
      </div>
    </div>}
  </section>
  {report && customer && <CustomerScanViews companyId={report.company.id} companyName={report.company.name} insights={customer.insights} />}
  </>;
}
