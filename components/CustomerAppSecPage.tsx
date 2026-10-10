"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import VulnShell from "./VulnShell";
import VulnAppSecPage from "./VulnAppSecPage";

export default function CustomerAppSecPage({ initialCompanyId = "" }: { initialCompanyId?: string }) {
  const router = useRouter();
  const [companyId, setCompanyId] = useState(initialCompanyId);
  const [setup, setSetup] = useState<{ reviewed: boolean; companies: { id: string; name: string }[] } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { setCompanyId(initialCompanyId); }, [initialCompanyId]);
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/appsec?setup=1", { cache: "no-store", signal: controller.signal }).then(async response => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load customer choices.");
      if (!controller.signal.aborted) setSetup(data);
    }).catch(e => { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Could not load customer choices."); });
    return () => controller.abort();
  }, []);
  const selection = setup?.reviewed ? <label className="flex flex-wrap items-center gap-3 text-sm text-zinc-300">
    Customer
    <select aria-label="Customer" className="max-w-full rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-white"
      value={companyId} onChange={event => { const next = event.target.value; setCompanyId(next); router.push(next ? `/appsec?companyId=${encodeURIComponent(next)}` : "/appsec"); }}>
      <option value="">Choose a customer</option>
      {setup.companies.map(company => <option key={company.id} value={company.id}>{company.name}</option>)}
    </select>
  </label> : null;
  if (setup && (!setup.reviewed || companyId && setup.companies.some(company => company.id === companyId)))
    return <VulnAppSecPage key={companyId || "organization"} companyId={companyId || undefined} selection={selection} />;
  return <VulnShell eyebrow="AppSec" title="Application security" subtitle="Customer repository coverage and software risk.">
    {selection}
    <p role="status" className="text-sm text-zinc-300">{error || (setup ? companyId ? "Customer not found. Choose an existing customer." : "Choose a customer to view its approved AppSec repositories." : "Loading customer choices...")}</p>
  </VulnShell>;
}
