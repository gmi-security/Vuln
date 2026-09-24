"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Monitor, RefreshCw, ShieldCheck } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { ghostButtonClass, PanelCard, StatCard } from "@/components/ui";
import type { ElasticCoverageView } from "@/lib/elastic-vuln";

export default function VulnElasticPage({ view: initialView }: { view: ElasticCoverageView }) {
  const [view, setView] = useState(initialView);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, []);
  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/elastic-vulnerabilities", { cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 401 ? "Your session expired. Sign in again." : "Unable to refresh. Previously loaded results are still shown.");
      setView(await response.json());
      setNow(Date.now());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to refresh.");
    } finally { setLoading(false); }
  }
  const sample = view.mode === "sample";
  const results = view.snapshot?.results;
  const stale = view.mode === "live" && view.snapshot && now !== null && now - Date.parse(view.snapshot.collectedAt) > 30 * 60_000;
  const labels = {
    sample: "Sample data preview — these figures are fictional. Live results are not connected.",
    unconfigured: "Awaiting the data connection. No live results are available yet.",
    empty: "The connection is ready. Waiting for the first successful query result.",
    unavailable: "Results are temporarily unavailable. Try refreshing shortly.",
    live: stale ? "Results are more than 30 minutes old. Showing the last successful query." : "Showing the latest saved query result.",
  };
  const cards = [
    { label: "Managed assets", value: results?.managed.toLocaleString("en-US") ?? "—", icon: <ShieldCheck size={24} /> },
    { label: "Unmanaged assets", value: results?.unmanaged.toLocaleString("en-US") ?? "—", icon: <Monitor size={24} /> },
    { label: "Asset coverage", value: results?.coverage_pct == null ? "—" : `${results.coverage_pct.toFixed(1)}%`, icon: <AlertTriangle size={24} /> },
  ];
  return (
    <VulnShell eyebrow="CrowdStrike · Elasticsearch" title="Elastic asset coverage"
      subtitle="Managed and unmanaged assets observed in your CrowdStrike Discover data."
      actions={<button type="button" className={ghostButtonClass} onClick={refresh} disabled={loading}>
        <RefreshCw size={16} aria-hidden="true" className={loading ? "animate-spin" : ""} />{loading ? "Refreshing…" : "Refresh results"}
      </button>}>
      <div role="status" className="rounded-2xl border border-amber-600/30 bg-amber-950/20 p-4 text-sm text-amber-200">
        {labels[view.mode]}
        <p className="mt-2 text-amber-200/75">Last successful query: {view.mode === "live" && view.snapshot
          ? new Date(view.snapshot.collectedAt).toISOString().replace("T", " ").replace(".000Z", " UTC") : "not yet available"}.</p>
      </div>
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      <div className="grid gap-4 lg:grid-cols-3">
        {cards.map((card) => <StatCard key={card.label} {...card} sublabel={sample ? "Sample data" : "Latest saved query"} />)}
      </div>
      <PanelCard eyebrow="Coverage breakdown" description="Coverage is managed ÷ (managed + unmanaged).">
        {results?.coverage_pct != null ? <>
          <div role="img" aria-label={`${results.coverage_pct}% managed; ${results.managed} managed and ${results.unmanaged} unmanaged assets`}
            className="flex h-5 overflow-hidden rounded-full bg-amber-500/70">
            <div className="h-full bg-emerald-500" style={{ width: `${results.coverage_pct}%` }} />
          </div>
          <div className="mt-3 flex flex-wrap justify-between gap-2 text-sm">
            <span className="text-emerald-400">Managed: {results.managed.toLocaleString("en-US")}</span>
            <span className="text-amber-400">Unmanaged: {results.unmanaged.toLocaleString("en-US")}</span>
          </div>
        </> : <p className="text-zinc-400">{results ? "No qualifying assets; coverage is not applicable." : "No results available."}</p>}
      </PanelCard>
      <PanelCard eyebrow="What this measures">
        <ul className="list-disc space-y-2 pl-5 text-sm text-zinc-400">
          <li>Records indexed with a timestamp in the last 25 hours.</li>
          <li>Assets last seen within the last seven days; future last-seen timestamps are excluded.</li>
          <li>Distinct asset IDs counted separately for managed and unmanaged records.</li>
          <li>An asset recorded under both categories can count in both. These are inventory coverage metrics, not vulnerability counts.</li>
        </ul>
      </PanelCard>
    </VulnShell>
  );
}
