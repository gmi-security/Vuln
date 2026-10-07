"use client";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import VulnShell from "./VulnShell";
import DefenderCustomerPanel, { defenderFetch } from "./DefenderCustomerPanel";
import { ghostButtonClass, inputClass, primaryButtonClass } from "./ui";
type Connection = { companyId:string; tenantId:string; clientId:string; daily:boolean; currentRun:string | null;
  status:string | null; phase:string; fetched:number; skipped:number; error:string | null; lastSuccessAt:string | null };
export default function DefenderConnectionsPage({ initialCompanyId = "" }: { initialCompanyId?: string }) {
  const [companies,setCompanies] = useState<{ id:string; name:string }[]>([]), [companyId,setCompanyId] = useState(initialCompanyId);
  const [connections,setConnections] = useState<Connection[]>([]), [loaded,setLoaded] = useState(false), [reload,setReload] = useState(0);
  const [tenantId,setTenantId] = useState(""), [clientId,setClientId] = useState(""), [clientSecret,setClientSecret] = useState(""), [daily,setDaily] = useState(false);
  const [busy,setBusy] = useState(""), [message,setMessage] = useState(""), [error,setError] = useState("");
  const saved = connections.find(row => row.companyId === companyId);
  const running = connections.some(row => row.status === "running" || row.status === "queued");
  const selectedRunning = saved?.status === "running" || saved?.status === "queued";
  useEffect(() => {
    const controller = new AbortController();
    defenderFetch("/api/companies", { signal:controller.signal }).then(body => setCompanies(body.companies))
      .catch(err => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  },[]);
  useEffect(() => {
    const controller = new AbortController();
    defenderFetch("/api/defender/connections", { signal:controller.signal }).then(body => { setConnections(body.connections); setLoaded(true); })
      .catch(err => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  },[reload]);
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => setReload(value=>value+1),10_000);
    return () => clearInterval(timer);
  },[running]);
  useEffect(() => {
    setTenantId(saved?.tenantId || ""); setClientId(saved?.clientId || ""); setClientSecret(""); setDaily(saved?.daily || false);
    setMessage(""); setError("");
  },[companyId,loaded]);
  async function action(kind: string) {
    setBusy(kind); setMessage(""); setError("");
    try {
      const data = await defenderFetch(kind === "sync" ? "/api/defender/import" : "/api/defender/connections", {
        method:"POST", headers:{ "Content-Type":"application/json" },
        body:JSON.stringify(kind === "sync" ? { companyId } : { action:kind,companyId,tenantId,clientId,clientSecret,daily }),
      });
      if (kind === "save") { setClientSecret(""); setMessage("Connection saved. Select Sync now to run the first import."); }
      else if (kind === "sync") setMessage("Import queued. You can leave this page; the import continues in the background.");
      else setMessage(data.message);
      setReload(value=>value+1);
    } catch (err) { setError(err instanceof Error ? err.message : "Request failed."); }
    finally { setBusy(""); }
  }
  return <VulnShell eyebrow="Customer integrations" title="Microsoft Defender" subtitle="Connect a customer's tenant, import its vulnerability assessment, and browse the saved results.">
    <div className="flex gap-3"><Link className={ghostButtonClass} href="/connectors">Back to connectors</Link>{companyId && <Link className={ghostButtonClass} href={`/companies/${encodeURIComponent(companyId)}`}>Customer page</Link>}</div>
    <section className="space-y-4 rounded-2xl border border-zinc-800 bg-[#090909] p-5">
      <h2 className="text-lg font-semibold">Customer connection</h2>
      <label className="block text-sm text-zinc-200">Customer<select aria-label="Customer" className={`${inputClass} mt-2 w-full`} value={companyId} disabled={!!busy} onChange={event => setCompanyId(event.target.value)}>
        <option value="">Select a customer</option>{companies.map(company => <option key={company.id} value={company.id}>{company.name}</option>)}
      </select></label>
      {!companies.length && <p className="text-sm text-zinc-300">Create the customer on the Companies page before configuring its connection.</p>}
      <fieldset disabled={!loaded || !companyId || !!busy || selectedRunning} className="grid gap-4 md:grid-cols-2 disabled:opacity-60">
        <label className="text-sm text-zinc-200">Directory / tenant ID<input autoComplete="off" className={`${inputClass} mt-2 w-full`} value={tenantId} onChange={event=>setTenantId(event.target.value.trim())} /></label>
        <label className="text-sm text-zinc-200">Application / client ID<input autoComplete="off" className={`${inputClass} mt-2 w-full`} value={clientId} onChange={event=>setClientId(event.target.value.trim())} /></label>
        <label className="text-sm text-zinc-200 md:col-span-2">Client secret value<input type="password" autoComplete="new-password" className={`${inputClass} mt-2 w-full`} value={clientSecret} onChange={event=>setClientSecret(event.target.value)} placeholder={saved ? "Secret saved — leave blank to keep it" : "Paste the secret value, not the secret ID"} /></label>
        <label className="flex items-center gap-3 text-sm text-zinc-200 md:col-span-2"><input type="checkbox" checked={daily} onChange={event=>setDaily(event.target.checked)} />Import daily after the first successful manual sync</label>
      </fieldset>
      <p className="text-sm text-zinc-300">Requires Defender for Endpoint / Vulnerability Management application permissions: Vulnerability.Read.All and Machine.Read.All, with administrator consent. Credentials are encrypted on the server.</p>
      <div className="flex flex-wrap gap-3">
        <button className={ghostButtonClass} disabled={!loaded || !companyId || !!busy || selectedRunning} onClick={()=>void action("test")}>{busy === "test" ? "Testing…" : "Test connection"}</button>
        <button className={primaryButtonClass} disabled={!loaded || !companyId || !!busy || selectedRunning} onClick={()=>void action("save")}>{busy === "save" ? "Saving…" : "Save connection"}</button>
        <button className={ghostButtonClass} disabled={!saved || !!busy || selectedRunning} onClick={()=>void action("sync")}>{selectedRunning ? `${saved.phase || "Queued"}…` : "Sync now"}</button>
      </div>
      {message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      {saved && <div className="rounded-xl border border-zinc-800 p-3 text-sm text-zinc-300">
        <p>Latest import: {saved.status || "Not started"}{saved.status ? ` · ${saved.phase} · ${(saved.fetched || 0).toLocaleString()} source rows processed` : ""}</p>
        {saved.skipped > 0 && <p>{saved.skipped.toLocaleString()} software rows contained no CVE and were excluded from findings.</p>}
        {saved.error && <p className="mt-2 text-red-300">{saved.error}</p>}
        <p className="mt-1">Last successful import: {saved.lastSuccessAt ? new Date(saved.lastSuccessAt).toLocaleString() : "Not yet available"}</p>
      </div>}
    </section>
    {companyId && <DefenderCustomerPanel key={companyId} companyId={companyId} refreshKey={saved?.currentRun || ""} />}
  </VulnShell>;
}
