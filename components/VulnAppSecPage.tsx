"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { RefreshCcw } from "lucide-react";
import {
  IconAlertTriangle,
  IconBug,
  IconFlame,
  IconGitBranch,
  IconKey,
  IconShieldX,
  IconTargetArrow,
  IconCircleCheck,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { KennaStatChip, ghostButtonClass } from "@/components/ui";
import { formatDateTime, severityBarColor } from "@/lib/format";
import type { AppSecRepoRow, AppSecSummary } from "@/lib/elastic-appsec";

const ROW_GRID = "grid grid-cols-[1.6fr_80px_80px_90px_90px_95px_110px_150px] items-center gap-4";

function gateColor(gate: string | null): string {
  if (!gate) return "#52525b";
  const g = gate.toLowerCase();
  if (g === "fail") return "#b30e14";
  if (g === "pass") return "#10b981";
  return "#f5a623";
}

function repoSeverityColor(row: AppSecRepoRow): string {
  if (row.critical > 0) return severityBarColor.Critical;
  if (row.high > 0) return severityBarColor.High;
  if (row.medium > 0) return severityBarColor.Medium;
  if (row.findings > 0) return severityBarColor.Low;
  return severityBarColor.Info;
}

export default function VulnAppSecPage() {
  const [configured, setConfigured] = useState(true);
  const [summary, setSummary] = useState<AppSecSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    try {
      const res = await fetch("/api/appsec", { cache: "no-store" });
      const json = await res.json();
      if (seq !== loadSeq.current) return;
      setConfigured(json.configured !== false);
      setSummary(json.summary ?? null);
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
      eyebrow="AppSec"
      title="Application security"
      subtitle="Trivy coverage and software risk across GMI GitHub repositories. Baseline debt stays visible; newly introduced High/Critical findings drive the gate."
      actions={
        <button onClick={() => void load()} className={ghostButtonClass}>
          <RefreshCcw size={16} className={loading ? "animate-spin text-zinc-400" : "text-zinc-400"} />
          Refresh
        </button>
      }
    >
      {!configured ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.06)] px-6 py-5 text-sm text-zinc-400">
          AppSec is not configured. Set <code className="text-zinc-300">APPSEC_ELASTIC_URL</code> and{" "}
          <code className="text-zinc-300">APPSEC_ELASTIC_API_KEY</code> with read access to{" "}
          <code className="text-zinc-300">gmi-appsec-scans</code> and <code className="text-zinc-300">gmi-appsec-findings</code>.
        </div>
      ) : error ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-6 py-5 text-sm text-[#ff4d57]">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KennaStatChip icon={<IconGitBranch size={16} />} label="Repositories scanned" value={summary ? summary.repositories : null} />
        <KennaStatChip icon={<IconTargetArrow size={16} />} label="Coverage %" value={summary ? summary.coveragePct : null} />
        <KennaStatChip icon={<IconAlertTriangle size={16} />} label="Critical open" value={summary ? summary.critical : null} tone="critical" />
        <KennaStatChip icon={<IconBug size={16} />} label="High open" value={summary ? summary.high : null} tone="warning" />
        <KennaStatChip icon={<IconFlame size={16} />} label="New critical" value={summary ? summary.newCritical : null} tone="critical" />
        <KennaStatChip icon={<IconFlame size={16} />} label="New high" value={summary ? summary.newHigh : null} tone="warning" />
        <KennaStatChip icon={<IconKey size={16} />} label="Secrets exposed" value={summary ? summary.secrets : null} tone="critical" pulse={Boolean(summary && summary.secrets > 0)} />
        <KennaStatChip icon={<IconShieldX size={16} />} label="Gate failures" value={summary ? summary.gateFailures : null} tone="critical" pulse={Boolean(summary && summary.gateFailures > 0)} />
        <KennaStatChip icon={<IconCircleCheck size={16} />} label="Resolved" value={summary ? summary.resolved : null} />
      </div>

      {summary ? (
        <div className="rounded-2xl border border-zinc-900 bg-[#060606] px-5 py-4 text-sm text-zinc-400">
          <span className="font-medium text-white">{summary.repositories}</span> of{" "}
          <span className="font-medium text-white">{summary.totalRepositories}</span> repositories reporting ·{" "}
          <span className="text-white">{summary.findings}</span> current findings ·{" "}
          <span className="text-white">{summary.vulnerabilities}</span> vulnerabilities ·{" "}
          <span className="text-white">{summary.misconfigurations}</span> misconfigurations ·{" "}
          <span className="text-white">{summary.licenses}</span> license findings
        </div>
      ) : null}

      <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
        <div className={`${ROW_GRID} border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500`}>
          <div>Repository</div>
          <div>Critical</div>
          <div>High</div>
          <div>New C/H</div>
          <div>Secrets</div>
          <div>Resolved</div>
          <div>Gate</div>
          <div>Last scan</div>
        </div>
        {(summary?.rows ?? []).map((row) => (
          <Link
            key={row.repository}
            href={`/appsec/repositories/${encodeURIComponent(row.repository)}`}
            className={`relative ${ROW_GRID} border-b border-zinc-900/70 px-5 py-4 transition last:border-b-0 hover:bg-[#0a0a0a]`}
          >
            <div className="absolute inset-y-0 left-0 w-[3px]" style={{ background: repoSeverityColor(row) }} />
            <div className="min-w-0 truncate font-medium text-white">{row.repository}</div>
            <div className="text-lg font-semibold tabular-nums" style={{ color: row.critical > 0 ? "#b30e14" : "#3f3f46" }}>{row.critical}</div>
            <div className="text-lg font-semibold tabular-nums" style={{ color: row.high > 0 ? "#f97316" : "#3f3f46" }}>{row.high}</div>
            <div className={`text-sm tabular-nums ${row.newCritical + row.newHigh > 0 ? "text-amber-300" : "text-zinc-700"}`}>
              {row.newCritical}/{row.newHigh}
            </div>
            <div className={`text-sm tabular-nums ${row.secrets > 0 ? "text-[#ff4d57]" : "text-zinc-700"}`}>{row.secrets}</div>
            <div className="text-sm tabular-nums text-emerald-400">{row.resolved}</div>
            <div>
              <span
                className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                style={{ borderColor: `${gateColor(row.gate)}55`, background: `${gateColor(row.gate)}22`, color: gateColor(row.gate) }}
              >
                {row.gate ?? "—"}
              </span>
            </div>
            <div className="text-sm text-zinc-400">{row.lastScan ? formatDateTime(row.lastScan) : "—"}</div>
          </Link>
        ))}
        {summary && summary.rows.length === 0 ? (
          <div className="px-5 py-12 text-center text-sm text-zinc-500">No completed AppSec scans yet.</div>
        ) : null}
        {!summary && configured && !error ? (
          <div className="px-5 py-12 text-center text-sm text-zinc-500">Loading…</div>
        ) : null}
      </div>
    </VulnShell>
  );
}
