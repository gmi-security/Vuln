"use client";
import CveText from "./CveText";
import RemediationWorklist from "./RemediationWorklist";
import FixTicketStatus from "./FixTicketStatus";
import { useEffect, useState } from "react";
import { readDashboardResponse } from "@/lib/dashboard-browser-client";
import type { TopFixesResult } from "@/lib/reporting-top-fixes";
import styles from "./QueryDashboard.module.css";

const format = (value: number) => value.toLocaleString();

export default function TopFixes({ companyId, canManage=false, refreshToken, reviewHref = "#consolidation-review" }: { companyId: string; canManage?:boolean; refreshToken?: number; reviewHref?: string }) {
  const [result, setResult] = useState<TopFixesResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [version, setVersion] = useState(0);
  // Never display the previous customer's rows while the next request loads.
  const data = result?.companyId === companyId ? result : null;
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45_000);
    setLoading(true); setError("");
    void (async () => {
      try {
        const response = await fetch(`/api/elastic-dashboard/top-fixes?companyId=${encodeURIComponent(companyId)}`, { signal: controller.signal, cache: "no-store" });
        const next = await readDashboardResponse<TopFixesResult>(response);
        if (next.companyId !== companyId) throw new Error("Top fixes returned a different customer.");
        if (active) setResult(next);
      } catch (cause) {
        if (active) setError(controller.signal.aborted ? "Top fixes took too long to load. Try Refresh." : cause instanceof Error ? cause.message : "Could not load top fixes.");
      } finally { clearTimeout(timeout); if (active) setLoading(false); }
    })();
    return () => { active = false; clearTimeout(timeout); controller.abort(); };
  }, [companyId, refreshToken, version]);
  const maxDevices = Math.max(1, ...(data?.rows.map(row => row.deviceCount) ?? []));

  return <><section className="rounded-2xl border border-[rgba(179,14,20,0.3)] bg-[#050505] p-5 sm:p-7" aria-label="Patching posture — top fixes" aria-busy={loading}>
    <p className="text-xs uppercase tracking-[0.25em] text-red-500">Patching posture</p>
    <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-2xl font-semibold text-white">Top fixes</h2>
      <button type="button" className={styles.button} disabled={loading} onClick={() => setVersion(v => v + 1)}>{loading ? "Loading…" : "Refresh"}</button>
    </div>
    <p className="mt-2 max-w-3xl text-sm text-zinc-300">Highest-impact fixes from this customer’s imported open vulnerabilities, ranked by affected devices. Includes findings in remediation, regardless of ticket or draft status.</p>
    {error && <p role="alert" className={styles.patchError}>{error}{data ? " Previously loaded results are shown." : ""}</p>}
    {!data && loading && <p role="status" className="mt-5 text-sm text-zinc-300">Loading open vulnerability fixes…</p>}
    {data && <>
      {data.notices?.map(notice=><p key={notice} role="status" className="mt-3 text-sm text-amber-200">{notice} Counts below cover available sources only.</p>)}
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {([["CVE / fix groups",data.totalFixes],[data.sources && data.sources.length>1 ? "Device records by source" : "Affected devices",data.affectedDevices],["Open findings with a fix",data.findingCount],[data.sources && data.sources.length>1 ? "CVE records by source" : "Unique CVEs with a fix",data.uniqueCves]] as const).map(([label,value]) =>
          <div key={label} className="rounded-xl border border-zinc-800 bg-black p-4">
            <p className="text-xs text-zinc-300">{label}</p>
            <strong className="mt-2 block text-3xl font-semibold tabular-nums text-white">{format(value)}</strong>
          </div>)}
      </div>
      <p className="mt-3 text-xs leading-relaxed text-zinc-300">Each group shares a CVE and remediation. Devices are counted once per group and source, using source asset identifiers. Different fixes can affect the same device. Across platform and CrowdStrike populations, device and CVE totals are source records, not a deduplicated estate count. Severity breaks device-count ties; risk breaks ties within a source. Completing a ticket does not confirm a vulnerability is resolved.</p>
      {data.missingRemediation > 0 && <p className="mt-3 text-sm text-amber-200">{format(data.missingRemediation)} additional open CVE findings have no recorded remediation and need investigation.</p>}
      {data.missingDevice > 0 && <p className="mt-3 text-sm text-amber-200">{format(data.missingDevice)} findings with a fix have no device identifier and are excluded from device counts.</p>}
      {!data.rows.length && !data.notices?.length && <p className="mt-6 text-sm text-zinc-300">No open CVE findings with recorded remediation are available for this customer. Check connector sync status if data is expected.</p>}
      {!!data.rows.length && <>
        <p className="mt-5 text-sm text-zinc-300">Showing {format(data.rows.length)} of {format(data.totalFixes)} CVE / fix groups. Click a CVE to review affected devices and prepare a patch request.</p>
        <ol className="mt-4 max-h-[36rem] space-y-3 overflow-y-auto pr-1" aria-label="Highest-impact fixes">
          {data.rows.map((row,index) => <li key={row.id} className="rounded-xl border border-zinc-800 bg-[#0a0a0a] p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-start gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[#b30e14] text-xs font-bold text-white">{index+1}</span>
                  <p className="max-h-24 overflow-auto break-words text-sm font-medium leading-relaxed text-white">{row.remediation}</p>
                </div>
                <p className="mt-2 text-sm text-zinc-200"><CveText text={row.cve}/></p>
              </div>
              <div className="shrink-0 text-right"><div className="text-2xl font-semibold text-white">{format(row.deviceCount)}</div><div className="text-xs text-zinc-300">devices</div></div>
            </div>
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-zinc-900" aria-hidden="true"><span className="block h-full rounded-full bg-[#b30e14]" style={{width:`${row.deviceCount/maxDevices*100}%`}}/></div>
            <p className="mt-2 text-xs text-zinc-300">{row.severity} · {row.source==="crowdstrike" ? "CrowdStrike / GMI patch score" : "Platform risk"} {format(row.maxRisk)} · {format(row.findingCount)} open findings</p>
            <FixTicketStatus status={row.ticketStatus} companyId={companyId}/>
          </li>)}
        </ol>
      </>}
    </>}
    <a href={reviewHref} className="mt-5 inline-block text-sm text-sky-300 underline underline-offset-2">View ticket queue</a>
  </section>
  <RemediationWorklist key={companyId} companyId={companyId} canManage={canManage} data={data?.remediationWorklist} loading={loading} onPrepared={()=>setVersion(v=>v+1)}/>
  </>;
}
