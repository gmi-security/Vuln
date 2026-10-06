"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowLeft, RefreshCcw } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { Pill, ghostButtonClass } from "@/components/ui";
import { formatDateTime, severityClass } from "@/lib/format";
import type { AppSecRepoDetail } from "@/lib/elastic-appsec";
import AppSecTrendChart from "@/components/AppSecTrendChart";

const SCAN_GRID = "grid grid-cols-[1fr_110px_85px_85px_85px_85px_110px] items-center gap-4";
const FINDING_GRID = "grid grid-cols-[95px_120px_1.6fr_1fr_110px_130px] items-center gap-4";

function gateColor(gate: string | null): string {
  if (!gate) return "#52525b";
  const g = gate.toLowerCase();
  if (g === "fail") return "#b30e14";
  if (g === "pass") return "#10b981";
  return "#f5a623";
}

export default function VulnAppSecRepoPage({ repository }: { repository: string }) {
  const [configured, setConfigured] = useState(true);
  const [detail, setDetail] = useState<AppSecRepoDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    try {
      const res = await fetch(`/api/appsec/repositories/${encodeURIComponent(repository)}`, { cache: "no-store" });
      const json = await res.json();
      if (seq !== loadSeq.current) return;
      setConfigured(json.configured !== false);
      setDetail(json.detail ?? null);
      setError(json.error ?? null);
    } catch {
      if (seq !== loadSeq.current) return;
      setError("Failed to reach the API.");
    } finally {
      if (seq === loadSeq.current) setLoading(false);
    }
  }, [repository]);

  useEffect(() => { void load(); }, [load]);

  const latest = detail?.scans[0];

  return (
    <VulnShell
      eyebrow="AppSec · Repository"
      title={repository}
      subtitle="Trivy scan history and current findings for this repository."
      actions={
        <>
          <Link href="/appsec" className={ghostButtonClass}>
            <ArrowLeft size={16} />
            All repositories
          </Link>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className={loading ? "animate-spin text-zinc-400" : "text-zinc-400"} />
            Refresh
          </button>
        </>
      }
    >
      {!configured ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.06)] px-6 py-5 text-sm text-zinc-400">
          AppSec is not configured.
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-6 py-5 text-sm text-[#ff4d57]">
          {error}
        </div>
      ) : null}

      {latest ? (
        <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] px-5 py-4">
          <span className="text-sm text-zinc-400">Latest scan</span>
          <span className="text-sm text-white">{formatDateTime(latest.completedAt)}</span>
          <span className="text-sm text-zinc-500">· {latest.findings} findings</span>
          <span className="text-sm text-zinc-500">· +{latest.newCritical} critical / +{latest.newHigh} high</span>
          <span className="text-sm text-zinc-500">· {latest.resolved} resolved</span>
          <span
            className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
            style={{ borderColor: `${gateColor(latest.gate)}55`, background: `${gateColor(latest.gate)}22`, color: gateColor(latest.gate) }}
          >
            {latest.gate ?? "—"} gate
          </span>
        </div>
      ) : null}

      <div className="rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404] px-5 py-5">
        <div className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
          Fixes &amp; criticality over time
        </div>
        <AppSecTrendChart points={detail?.scans ?? []} />
      </div>

      <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
        <div className={`${SCAN_GRID} border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500`}>
          <div>Scan</div>
          <div>Status</div>
          <div>Critical</div>
          <div>High</div>
          <div>New C</div>
          <div>New H</div>
          <div>Gate</div>
        </div>
        {(detail?.scans ?? []).map((scan) => (
          <div key={scan.scanId} className={`${SCAN_GRID} border-b border-zinc-900/70 px-5 py-4 last:border-b-0`}>
            <div className="min-w-0">
              <div className="truncate text-sm text-white">{formatDateTime(scan.completedAt)}</div>
              <div className="mt-0.5 truncate text-xs text-zinc-600">{scan.scanId}</div>
            </div>
            <div className="text-sm text-zinc-300">{scan.status ?? "—"}</div>
            <div className="text-sm font-semibold tabular-nums" style={{ color: scan.critical > 0 ? "#b30e14" : "#3f3f46" }}>{scan.critical}</div>
            <div className="text-sm font-semibold tabular-nums" style={{ color: scan.high > 0 ? "#f97316" : "#3f3f46" }}>{scan.high}</div>
            <div className="text-sm tabular-nums text-[#ff4d57]">{scan.newCritical}</div>
            <div className="text-sm tabular-nums text-amber-300">{scan.newHigh}</div>
            <div>
              <span
                className="rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                style={{ borderColor: `${gateColor(scan.gate)}55`, background: `${gateColor(scan.gate)}22`, color: gateColor(scan.gate) }}
              >
                {scan.gate ?? "—"}
              </span>
            </div>
          </div>
        ))}
        {detail && detail.scans.length === 0 ? (
          <div className="px-5 py-10 text-center text-sm text-zinc-500">No completed scans for this repository yet.</div>
        ) : null}
      </div>

      <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
        <div className="border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
          Current findings
        </div>
        {detail?.findingsError ? (
          <div className="px-5 py-8 text-center text-sm text-zinc-500">
            Findings unavailable: {detail.findingsError}
          </div>
        ) : (
          <>
            <div className={`${FINDING_GRID} border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500`}>
              <div>Severity</div>
              <div>Type</div>
              <div>Finding</div>
              <div>Package / Target</div>
              <div>Status</div>
              <div>Observed</div>
            </div>
            {(detail?.findings ?? []).map((f) => (
              <div key={f.fingerprint || f.id} className={`${FINDING_GRID} border-b border-zinc-900/70 px-5 py-4 last:border-b-0`}>
                <div>
                  <Pill className={severityClass[f.severity as keyof typeof severityClass] ?? severityClass.Info}>
                    {f.severity}
                  </Pill>
                </div>
                <div className="truncate text-xs uppercase tracking-wide text-zinc-500">{f.kind}</div>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-white">{f.title}</div>
                  {(f.vulnerabilityId || f.id) ? (
                    <div className="mt-0.5 text-xs text-[#ff8f96]">{f.vulnerabilityId || f.id}</div>
                  ) : null}
                </div>
                <div className="min-w-0 truncate text-sm text-zinc-300">{f.package ?? f.target ?? "—"}</div>
                <div className="text-sm text-zinc-400">{f.status ?? "—"}</div>
                <div className="text-sm text-zinc-400">{f.observedAt ? formatDateTime(f.observedAt) : "—"}</div>
              </div>
            ))}
            {detail && detail.findings.length === 0 ? (
              <div className="px-5 py-10 text-center text-sm text-zinc-500">No current findings.</div>
            ) : null}
          </>
        )}
      </div>
    </VulnShell>
  );
}
