"use client";
import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import styles from "./QueryDashboard.module.css";

const TOP_N = 10;
const format = (value: number) => value.toLocaleString();

export default function TopFixes({ companyId, refreshToken }: { companyId: string; refreshToken?: number }) {
  const [rows, setRows] = useState<PatchGroupTicketSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const all: PatchGroupTicketSummary[] = [];
      let page = 1, hasMore = true;
      while (hasMore && page <= 10_000) {
        const data = await dashboardRequest<{ requests: PatchGroupTicketSummary[]; more: boolean }>(`patch-group-tickets?review=1&page=${page}&companyId=${encodeURIComponent(companyId)}`);
        all.push(...data.requests);
        hasMore = data.more;
        page++;
      }
      setRows(all);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load patching posture."); }
    finally { setLoading(false); }
  }, [companyId]);
  useEffect(() => { void reload(); }, [reload, refreshToken]);

  const pending = rows.filter(row => row.reviewState === "pending")
    .sort((a, b) => b.hostCount - a.hostCount || b.findingCount - a.findingCount);
  const totalDevices = pending.reduce((sum, row) => sum + row.hostCount, 0);
  const totalFindings = pending.reduce((sum, row) => sum + row.findingCount, 0);
  const distinctCves = new Set(pending.flatMap(row => row.cves)).size;
  const topTen = pending.slice(0, TOP_N);
  const topTenDevices = topTen.reduce((sum, row) => sum + row.hostCount, 0);
  const topTenShare = totalDevices > 0 ? Math.round((topTenDevices / totalDevices) * 100) : 0;
  const top = pending;
  const maxDevices = Math.max(1, ...top.map(row => row.hostCount));

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.3)] bg-[#050505] p-5 sm:p-7" aria-label="Patching posture — top fixes">
    <p className="text-xs uppercase tracking-[0.25em] text-red-500">Patching posture</p>
    <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-2xl font-semibold text-white">Top fixes</h2>
      <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
    </div>
    <p className="mt-2 max-w-3xl text-sm text-zinc-400">The fewest remediation actions that close the most exposure for this customer, ranked by devices affected — apply these first.</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}

    <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <div className="rounded-xl border border-zinc-800 bg-black p-4">
        <p className="text-xs text-zinc-400">Remediations needed</p>
        <strong className="mt-2 block text-3xl font-semibold tabular-nums text-white">{format(pending.length)}</strong>
        <p className="mt-2 text-xs text-zinc-500">Distinct patch actions awaiting review</p>
      </div>
      <div className="rounded-xl border border-zinc-800 bg-black p-4">
        <p className="text-xs text-zinc-400">Devices covered</p>
        <strong className="mt-2 block text-3xl font-semibold tabular-nums text-white">{format(totalDevices)}</strong>
        <p className="mt-2 text-xs text-zinc-500">Device-remediation pairs; one device can need more than one fix</p>
      </div>
      <div className="rounded-xl border border-zinc-800 bg-black p-4">
        <p className="text-xs text-zinc-400">Findings closed if applied</p>
        <strong className="mt-2 block text-3xl font-semibold tabular-nums text-white">{format(totalFindings)}</strong>
        <p className="mt-2 text-xs text-zinc-500">{format(distinctCves)} distinct CVEs across pending remediations</p>
      </div>
      <div className="rounded-xl border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] p-4">
        <p className="text-xs text-zinc-400">Top {Math.min(TOP_N, pending.length)} fixes alone close</p>
        <strong className="mt-2 block text-3xl font-semibold tabular-nums text-[#ff8f96]">{pending.length ? `${topTenShare}%` : "—"}</strong>
        <p className="mt-2 text-xs text-zinc-500">Of all devices needing a fix, from this many actions</p>
      </div>
    </div>

    {!loading && !pending.length && <p className="mt-6 text-sm text-zinc-400">No remediations awaiting review. Everything pending is either approved or there is nothing to patch right now.</p>}
    {pending.length > 0 && <p className="mt-6 text-sm text-zinc-400">Every pending remediation, full picture — 100% ranked by devices affected, no cutoff.</p>}

    {top.length > 0 && <ol className="mt-6 space-y-3">
      {top.map((row, index) => {
        const share = totalDevices > 0 ? Math.round((row.hostCount / totalDevices) * 1000) / 10 : 0;
        return <li key={row.id} className="rounded-xl border border-zinc-800 bg-[#0a0a0a] p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[#b30e14] text-xs font-bold text-white">{index + 1}</span>
                <span className="font-medium text-white">{row.remediationTitle || "Recommended remediation"}</span>
              </div>
              <p className="mt-2 text-xs text-zinc-500">{row.cves.length === 1 ? row.cves[0] : `${row.cves.length} CVEs, including ${row.cves.slice(0, 2).join(", ")}`}</p>
            </div>
            <div className="shrink-0 text-right">
              <div className="text-2xl font-semibold text-white">{format(row.hostCount)}</div>
              <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-600">devices</div>
            </div>
          </div>
          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-zinc-900" aria-hidden="true">
            <span className="block h-full rounded-full bg-[#b30e14]" style={{ width: `${(row.hostCount / maxDevices) * 100}%` }} />
          </div>
          <div className="mt-1.5 flex flex-wrap items-center justify-between gap-2 text-[11px] text-zinc-500">
            <span>{share}% of pending exposure · {format(row.findingCount)} findings</span>
            <a href="#consolidation-review" className="text-sky-300 underline underline-offset-2">Review &amp; approve in queue below</a>
          </div>
        </li>;
      })}
    </ol>}
  </section>;
}
