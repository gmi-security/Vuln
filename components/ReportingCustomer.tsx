"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ConnectWiseSelect } from "@/components/ConnectWiseFields";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { ExecReport } from "@/lib/store";
import { selectClass } from "@/components/ui";

type Setup = { configured: boolean; revision?: number; companies: { id: string; name: string }[] };
type Customer = { linked: false } | { linked: true; appCompanyId: string; cwCompanyName: string; report: ExecReport; sources: { name: string; open: number }[] };
const number = (value: number) => value.toLocaleString();

export default function ReportingCustomer() {
  const [setup, setSetup] = useState<Setup | null>(null);
  const [setupVersion, setSetupVersion] = useState(0);
  const [cwCompanyId, setCwCompanyId] = useState<number>();
  const [appCompanyId, setAppCompanyId] = useState("");
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editingLink, setEditingLink] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    dashboardRequest<Setup>("reporting").then(data => { if (active) setSetup(data); })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Reporting is unavailable."); });
    return () => { active = false; };
  }, [setupVersion]);
  useEffect(() => {
    if (!cwCompanyId) { setCustomer(null); return; }
    let active = true;
    setCustomer(null); setEditingLink(false); setLoading(true); setError("");
    dashboardRequest<Customer>(`reporting?cwCompanyId=${cwCompanyId}`)
      .then(data => { if (active) { setCustomer(data); setAppCompanyId(data.linked ? data.appCompanyId : ""); } })
      .catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "Customer report is unavailable."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [cwCompanyId]);

  async function linkCompany() {
    if (!cwCompanyId || !appCompanyId) return;
    setSaving(true); setError("");
    try {
      await dashboardRequest("reporting", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cwCompanyId, appCompanyId }) });
      setCustomer(await dashboardRequest<Customer>(`reporting?cwCompanyId=${cwCompanyId}`));
      setEditingLink(false);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not link the customer."); }
    finally { setSaving(false); }
  }

  const report = customer?.linked ? customer.report : null;
  return <section aria-label="Customer report" className="rounded-2xl border border-zinc-800 bg-[#090909] p-5 sm:p-7">
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-zinc-800 pb-5">
      <div><p className="text-xs uppercase tracking-[0.25em] text-red-500">Customer reporting</p>
        <h2 className="mt-2 text-2xl font-semibold text-white">Customer report</h2>
        <p className="mt-2 max-w-2xl text-sm text-zinc-400">Select a ConnectWise company to see findings from its linked customer, across all connected scanners.</p></div>
      {report && <Link href={`/report/${encodeURIComponent(report.company.id)}`} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-100 hover:bg-zinc-800">Open full report</Link>}
    </div>
    {!setup && !error && <p role="status" className="text-sm text-zinc-400">Loading customer reporting…</p>}
    {setup && !setup.configured && <div className="rounded-lg border border-amber-900 bg-amber-950/20 p-4 text-sm text-amber-200">ConnectWise is not configured. Add it under Connections to select a customer. <button type="button" className="ml-2 underline" onClick={() => setSetupVersion(version => version + 1)}>Check again</button></div>}
    {setup?.configured && <div className="max-w-xl"><ConnectWiseSelect label="Customer" kind="companies" value={cwCompanyId} onChange={setCwCompanyId} revision={setup.revision} /></div>}
    {error && <p role="alert" className="mt-4 text-sm text-red-300">{error}</p>}
    {loading && <p role="status" className="mt-5 text-sm text-zinc-400">Loading this customer’s report…</p>}
    {setup?.configured && cwCompanyId && customer && (!customer.linked || editingLink) && <div className="mt-6 max-w-2xl rounded-xl border border-zinc-700 bg-zinc-950 p-5">
      <h3 className="font-medium text-white">{customer.linked ? "Change customer link" : "Link this ConnectWise company"}</h3>
      <p className="mt-2 text-sm text-zinc-400">Choose the matching customer in this app. This link is saved for future reports.</p>
      <label className="mt-4 block text-sm text-zinc-200">App customer
        <select className={`${selectClass} mt-2 block w-full`} value={appCompanyId} onChange={event => setAppCompanyId(event.target.value)}>
          <option value="">Choose a customer</option>
          {setup.companies.map(company => <option key={company.id} value={company.id}>{company.name} ({company.id})</option>)}
        </select>
      </label>
      <button type="button" className="mt-4 rounded-lg bg-[#b30e14] px-4 py-2 text-sm font-medium text-white disabled:opacity-40" disabled={!appCompanyId || saving} onClick={() => void linkCompany()}>{saving ? "Saving…" : "Link customer"}</button>
      {customer.linked && <button type="button" className="ml-3 text-sm text-zinc-400 hover:text-white" onClick={() => setEditingLink(false)}>Cancel</button>}
    </div>}
    {report && customer?.linked && <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-xl font-medium text-white">{report.company.name}</h3>
        <p className="mt-1 text-xs text-zinc-500">ConnectWise: {customer.cwCompanyName} · Updated {new Date(report.generatedAt).toLocaleString()}</p></div>
        {!editingLink && <button type="button" className="text-sm text-zinc-400 underline hover:text-white" onClick={() => setEditingLink(true)}>Change link</button>}</div>
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
  </section>;
}
