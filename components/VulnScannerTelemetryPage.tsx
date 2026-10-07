"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCcw } from "lucide-react";
import {
  IconAlertTriangle,
  IconBug,
  IconFlame,
  IconDatabase,
  IconServer2,
  IconShieldBolt,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { KennaStatChip, ghostButtonClass } from "@/components/ui";
import type { ScannerSummary, ScannerCompanyRow } from "@/lib/elastic-scanner-dashboard";

const ROW_GRID = "grid grid-cols-[1.8fr_110px_110px_110px] items-center gap-4";

export default function VulnScannerTelemetryPage() {
  const [configured, setConfigured] = useState(true);
  const [summary, setSummary] = useState<ScannerSummary | null>(null);
  const [companies, setCompanies] = useState<ScannerCompanyRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    try {
      const res = await fetch("/api/scanner-dashboard", { cache: "no-store" });
      const json = await res.json();
      if (seq !== loadSeq.current) return;
      setConfigured(json.configured !== false);
      setSummary(json.summary ?? null);
      setCompanies(json.companies ?? null);
      setError(json.error ?? null);
    } catch {
      if (seq !== loadSeq.current) return;
      setError("Failed to reach the API.");
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <VulnShell
      eyebrow="Scanner Telemetry"
      title="Nessus &amp; Vulners bridge"
      subtitle="Raw scanner findings exported from the app's own store into Elastic -- gmi-nessus-findings and gmi-vulners-findings, each its own index, tagged by source."
      actions={
        <button onClick={() => void load()} className={ghostButtonClass}>
          <RefreshCcw size={16} className={loading ? "animate-spin text-zinc-400" : "text-zinc-400"} />
          Refresh
        </button>
      }
    >
      {!configured ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.06)] px-6 py-5 text-sm text-zinc-400">
          Scanner telemetry export is not configured. Set <code className="text-zinc-300">SCANNER_ELASTIC_URL</code> and{" "}
          <code className="text-zinc-300">SCANNER_ELASTIC_API_KEY</code> (or the <code className="text-zinc-300">APPSEC_ELASTIC_*</code> fallback)
          with write access to <code className="text-zinc-300">gmi-nessus-findings</code> and <code className="text-zinc-300">gmi-vulners-findings</code>.
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-6 py-5 text-sm text-[#ff4d57]">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KennaStatChip icon={<IconDatabase size={16} />} label="Total findings" value={summary ? summary.totalFindings : null} />
        <KennaStatChip icon={<IconServer2 size={16} />} label="Nessus" value={summary ? summary.nessusFindings : null} />
        <KennaStatChip icon={<IconServer2 size={16} />} label="Vulners bridge" value={summary ? summary.vulnersFindings : null} />
        <KennaStatChip icon={<IconAlertTriangle size={16} />} label="Critical" value={summary ? summary.critical : null} tone="critical" />
        <KennaStatChip icon={<IconBug size={16} />} label="High" value={summary ? summary.high : null} tone="warning" />
        <KennaStatChip icon={<IconFlame size={16} />} label="Medium" value={summary ? summary.medium : null} />
        <KennaStatChip icon={<IconFlame size={16} />} label="Low" value={summary ? summary.low : null} />
        <KennaStatChip
          icon={<IconShieldBolt size={16} />}
          label="Exploit available"
          value={summary ? summary.exploitAvailable : null}
          tone="critical"
          pulse={Boolean(summary && summary.exploitAvailable > 0)}
        />
      </div>

      <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
        <div className={`${ROW_GRID} border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500`}>
          <div>Company</div>
          <div>Nessus</div>
          <div>Vulners</div>
          <div>Total</div>
        </div>
        {(companies ?? []).map((row) => (
          <div
            key={row.companyId}
            className={`${ROW_GRID} border-b border-zinc-900/70 px-5 py-4 last:border-b-0`}
          >
            <div className="min-w-0 truncate font-medium text-white">{row.companyName || row.companyId}</div>
            <div className="text-sm tabular-nums text-zinc-300">{row.nessus}</div>
            <div className="text-sm tabular-nums text-zinc-300">{row.vulners}</div>
            <div className="text-sm font-semibold tabular-nums text-white">{row.total}</div>
          </div>
        ))}
        {companies && companies.length === 0 ? (
          <div className="px-5 py-12 text-center text-sm text-zinc-500">No scanner findings exported yet.</div>
        ) : null}
        {!companies && configured && !error ? (
          <div className="px-5 py-12 text-center text-sm text-zinc-500">Loading…</div>
        ) : null}
      </div>
    </VulnShell>
  );
}
