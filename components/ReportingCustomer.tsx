"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import CustomerReportSections from "@/components/reporting/CustomerReportSections";
import type { CustomerReportingModel } from "@/lib/reporting-customer-model";
import type { ExecReport } from "@/lib/store";
import { selectClass } from "@/components/ui";

type Setup = { companies: { id: string; name: string }[] };
type Customer = { report: ExecReport; model: CustomerReportingModel };

export default function ReportingCustomer({ companyId, onCompanyChange, refreshToken }: { companyId: string; onCompanyChange: (companyId: string) => void; refreshToken: number }) {
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
    if (!companyId) { setCustomer(null); setLoading(false); setError(""); return; }
    let active = true;
    setCustomer(null); setLoading(true); setError("");
    dashboardRequest<Customer>(`reporting?companyId=${encodeURIComponent(companyId)}`)
      .then(data => { if (active) setCustomer(data); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Customer report is unavailable."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [companyId, refreshToken]);

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
    {report && customer && customer.model.company.id === companyId && <CustomerReportSections model={customer.model} />}
  </section>
  </>;
}
