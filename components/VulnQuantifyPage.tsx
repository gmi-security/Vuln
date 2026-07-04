"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { RefreshCcw } from "lucide-react";
import {
  IconAlertTriangle,
  IconClockHour4,
  IconFlame,
  IconGauge,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill, StatCard, ghostButtonClass } from "@/components/ui";
import {
  compositeBandClass,
  compositeColor,
  connectorLabels,
  exposureClass,
  riskColor,
  severityBarColor,
  severityClass,
} from "@/lib/format";
import type { QuantifyMetrics, Severity } from "@/lib/types";

const COMPOSITE_COMPONENTS: {
  key: "exposure" | "kevPressure" | "slaBreach" | "coverageGap";
  label: string;
  weight: string;
  hint: string;
}[] = [
  {
    key: "exposure",
    label: "Open exposure",
    weight: "40%",
    hint: "Severity × exploitability × EPSS across open findings",
  },
  {
    key: "kevPressure",
    label: "Active exploitation",
    weight: "25%",
    hint: "Share of open findings in CISA KEV (exploited in the wild)",
  },
  {
    key: "slaBreach",
    label: "SLA breaches",
    weight: "20%",
    hint: "Share of open findings past their remediation SLA",
  },
  {
    key: "coverageGap",
    label: "Coverage gap",
    weight: "15%",
    hint: "Known inventory assets with no scan coverage",
  },
];

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

type RiskBand = "Critical" | "High" | "Medium" | "Low" | "Info";
const RISK_BANDS: RiskBand[] = ["Critical", "High", "Medium", "Low", "Info"];
const riskBandColor: Record<RiskBand, string> = {
  Critical: "#b30e14",
  High: "#f97316",
  Medium: "#f5a623",
  Low: "#4aa3ff",
  Info: "#52525b",
};

export default function VulnQuantifyPage() {
  const [metrics, setMetrics] = useState<QuantifyMetrics | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/metrics", { cache: "no-store" });
      const json = await res.json();
      setMetrics(json.metrics ?? null);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const maxSeverity = Math.max(
    1,
    ...SEVERITIES.map((s) => metrics?.severityCounts[s] ?? 0),
  );
  const slaTotal = Math.max(
    1,
    (metrics?.slaBuckets ?? []).reduce((sum, b) => sum + b.count, 0),
  );
  const maxAssetScore = Math.max(
    1,
    ...(metrics?.assetRisk ?? []).map((a) => a.score),
  );

  return (
    <VulnShell
      eyebrow="Quantify"
      title="Risk quantification"
      subtitle="Exposure scoring, SLA posture, remediation velocity, and asset-level risk — the numbers behind the vulnerability program."
      actions={
        <button onClick={() => void load()} className={ghostButtonClass}>
          <RefreshCcw size={16} className="text-zinc-400" />
          Refresh
        </button>
      }
    >
      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Exposure score"
          value={metrics ? metrics.exposureScore : "—"}
          sublabel="Severity × exploitability × EPSS, 0–100"
          icon={<IconGauge size={26} />}
        />
        <StatCard
          label="Actively exploited"
          value={metrics ? metrics.kevOpen : "—"}
          sublabel={`In CISA KEV · ${metrics?.exploitableOpen ?? 0} with public exploit`}
          icon={<IconFlame size={26} />}
        />
        <StatCard
          label="SLA breaches"
          value={
            metrics
              ? metrics.slaBuckets.find((b) => b.breach)?.count ?? 0
              : "—"
          }
          sublabel="Open findings past remediation SLA"
          icon={<IconAlertTriangle size={26} />}
        />
        <StatCard
          label="Mean time to remediate"
          value={
            metrics?.meanTimeToRemediateDays != null
              ? `${metrics.meanTimeToRemediateDays}d`
              : "—"
          }
          sublabel="Across resolved findings"
          icon={<IconClockHour4 size={26} />}
        />
      </div>

      <PanelCard
        eyebrow="Composite security posture"
        description="One score blending open exposure, active exploitation, SLA breaches, and scan-coverage gaps"
      >
        <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
          <div className="flex flex-col items-center justify-center rounded-[24px] border border-[rgba(179,14,20,0.16)] bg-[#040404] p-6 text-center">
            <div
              className="text-6xl font-semibold tracking-[-0.04em]"
              style={{ color: compositeColor(metrics?.composite.score ?? 0) }}
            >
              {metrics ? metrics.composite.score : "—"}
            </div>
            <div className="mt-1 text-sm text-zinc-500">/ 100</div>
            {metrics ? (
              <div className="mt-3">
                <Pill className={compositeBandClass[metrics.composite.band]}>
                  {metrics.composite.band}
                </Pill>
              </div>
            ) : null}
          </div>
          <div className="space-y-4">
            {COMPOSITE_COMPONENTS.map((comp) => {
              const val = metrics?.composite.components[comp.key] ?? 0;
              return (
                <div key={comp.key}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="text-zinc-300">
                      {comp.label}{" "}
                      <span className="text-xs text-zinc-600">
                        · weight {comp.weight}
                      </span>
                    </span>
                    <span className="font-medium text-white">{val}</span>
                  </div>
                  <div className="h-3 overflow-hidden rounded-full bg-[#101010]">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${val}%`,
                        background: compositeColor(val),
                      }}
                    />
                  </div>
                  <p className="mt-1 text-xs text-zinc-600">{comp.hint}</p>
                </div>
              );
            })}
          </div>
        </div>
      </PanelCard>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <PanelCard
          eyebrow="Real-risk priority"
          description="Open findings by composite real-risk band"
        >
          <div className="space-y-3">
            {RISK_BANDS.map((band) => {
              const count = metrics?.riskPriorityCounts[band] ?? 0;
              const total = Math.max(
                1,
                RISK_BANDS.reduce(
                  (sum, b) => sum + (metrics?.riskPriorityCounts[b] ?? 0),
                  0,
                ),
              );
              return (
                <div key={band} className="flex items-center gap-3">
                  <div className="w-20 text-sm text-zinc-400">{band}</div>
                  <div className="h-3 flex-1 overflow-hidden rounded-full bg-[#101010]">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.round((count / total) * 100)}%`,
                        background: riskBandColor[band],
                      }}
                    />
                  </div>
                  <div className="w-8 text-right text-sm font-medium text-white">
                    {count}
                  </div>
                </div>
              );
            })}
          </div>
          <p className="mt-5 text-xs leading-relaxed text-zinc-500">
            Real risk = base CVSS adjusted for exploitation in the wild (CISA
            KEV, EPSS, public exploit) and each asset&apos;s exposure and
            business criticality.
          </p>
        </PanelCard>

        <PanelCard
          eyebrow="Top real-risk findings"
          description="Highest composite risk across the environment"
        >
          <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
            <div className="grid grid-cols-[70px_1.7fr_1.1fr_130px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
              <div>Risk</div>
              <div>Finding</div>
              <div>Asset</div>
              <div>Client</div>
            </div>
            {(metrics?.topRisks ?? []).slice(0, 8).map((r) => (
              <Link
                key={r.id}
                href={`/findings?focus=${r.id}`}
                className="grid grid-cols-[70px_1.7fr_1.1fr_130px] items-center gap-4 border-b border-zinc-900/70 px-5 py-3 transition last:border-b-0 hover:bg-[#0a0a0a]"
              >
                <div
                  className="text-lg font-semibold"
                  style={{ color: riskColor(r.realRisk) }}
                >
                  {r.realRisk}
                </div>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-white">
                    {r.title}
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-zinc-500">
                    <span className="text-[#ff8f96]">{r.cve}</span>
                    {r.kev ? (
                      <span className="rounded-full border border-[rgba(179,14,20,0.55)] bg-[rgba(179,14,20,0.16)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-[#ff4d57]">
                        KEV
                      </span>
                    ) : null}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="truncate text-sm text-zinc-300">{r.asset}</div>
                  <div
                    className={`mt-1 text-xs ${exposureClass[r.exposure] ?? "text-zinc-500"}`}
                  >
                    {r.exposure}
                  </div>
                </div>
                <div className="truncate text-sm text-zinc-400">
                  {r.companyName}
                </div>
              </Link>
            ))}
            {(metrics?.topRisks ?? []).length === 0 ? (
              <div className="px-5 py-10 text-center text-sm text-zinc-500">
                No open findings.
              </div>
            ) : null}
          </div>
        </PanelCard>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <PanelCard
          eyebrow="Open findings trend"
          description="Open backlog and daily resolutions, last 14 days"
        >
          <TrendChart trend={metrics?.trend ?? []} />
        </PanelCard>

        <PanelCard
          eyebrow="SLA posture"
          description="Remediation SLA: Critical 7d · High 30d · Medium 90d · Low 180d"
        >
          <div className="space-y-4">
            {(metrics?.slaBuckets ?? []).map((bucket) => (
              <div key={bucket.label}>
                <div className="mb-2 flex items-center justify-between text-sm">
                  <span
                    className={bucket.breach ? "text-[#ff4d57]" : "text-zinc-300"}
                  >
                    {bucket.label}
                  </span>
                  <span className="font-medium text-white">{bucket.count}</span>
                </div>
                <div className="h-3 overflow-hidden rounded-full bg-[#101010]">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.round((bucket.count / slaTotal) * 100)}%`,
                      background: bucket.breach
                        ? "linear-gradient(90deg,#b30e14,#ff4d57)"
                        : bucket.label.startsWith("Due")
                          ? "#f5a623"
                          : "#10b981",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 border-t border-zinc-900 pt-5">
            <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
              Open by severity
            </div>
            <div className="mt-4 space-y-3">
              {SEVERITIES.map((severity) => {
                const count = metrics?.severityCounts[severity] ?? 0;
                return (
                  <div key={severity} className="flex items-center gap-3">
                    <div className="w-16 text-sm text-zinc-400">{severity}</div>
                    <div className="h-3 flex-1 overflow-hidden rounded-full bg-[#101010]">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${Math.round((count / maxSeverity) * 100)}%`,
                          background: severityBarColor[severity],
                        }}
                      />
                    </div>
                    <div className="w-8 text-right text-sm font-medium text-white">
                      {count}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </PanelCard>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <PanelCard
          eyebrow="Asset risk ranking"
          description="Severity-weighted score per asset; exploitable findings weigh 1.5×"
        >
          <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
            <div className="grid grid-cols-[1.4fr_1fr_110px_110px_110px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
              <div>Asset</div>
              <div>Risk</div>
              <div>Score</div>
              <div>Open</div>
              <div>Worst</div>
            </div>
            {(metrics?.assetRisk ?? []).map((asset) => (
              <div
                key={asset.asset}
                className="grid grid-cols-[1.4fr_1fr_110px_110px_110px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 last:border-b-0"
              >
                <div className="truncate font-medium text-white">
                  {asset.asset}
                </div>
                <div className="h-2.5 overflow-hidden rounded-full bg-[#101010]">
                  <div
                    className="h-full rounded-full bg-[linear-gradient(90deg,#b30e14,#ff4d57)]"
                    style={{
                      width: `${Math.round((asset.score / maxAssetScore) * 100)}%`,
                    }}
                  />
                </div>
                <div className="text-sm font-semibold text-white">
                  {asset.score}
                </div>
                <div className="text-sm text-zinc-300">{asset.open}</div>
                <div>
                  <Pill className={severityClass[asset.worst]}>
                    {asset.worst}
                  </Pill>
                </div>
              </div>
            ))}
            {(metrics?.assetRisk ?? []).length === 0 ? (
              <div className="px-5 py-12 text-center text-sm text-zinc-500">
                No open findings to rank.
              </div>
            ) : null}
          </div>
        </PanelCard>

        <div className="space-y-5">
          <PanelCard
            eyebrow="Findings by source"
            description="Open findings per connector"
          >
            <div className="space-y-2">
              {(metrics?.connectorCounts ?? []).map((entry) => (
                <div
                  key={entry.connector}
                  className="flex items-center justify-between rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3"
                >
                  <span className="text-sm text-zinc-300">
                    {connectorLabels[entry.connector]}
                  </span>
                  <span className="text-lg font-semibold text-white">
                    {entry.open}
                  </span>
                </div>
              ))}
            </div>
          </PanelCard>

          <PanelCard
            eyebrow="Workflow status"
            description="All findings by triage state"
          >
            <div className="space-y-2">
              {Object.entries(metrics?.statusCounts ?? {}).map(
                ([status, count]) => (
                  <div
                    key={status}
                    className="flex items-center justify-between rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3"
                  >
                    <span className="text-sm text-zinc-300">{status}</span>
                    <span className="text-lg font-semibold text-white">
                      {count}
                    </span>
                  </div>
                ),
              )}
            </div>
          </PanelCard>
        </div>
      </div>
    </VulnShell>
  );
}

function TrendChart({
  trend,
}: {
  trend: QuantifyMetrics["trend"];
}) {
  if (!trend.length) {
    return (
      <div className="py-12 text-center text-sm text-zinc-500">
        No trend data yet.
      </div>
    );
  }
  const width = 640;
  const height = 220;
  const pad = 28;
  const maxOpen = Math.max(1, ...trend.map((t) => t.open));
  const step = (width - pad * 2) / Math.max(1, trend.length - 1);
  const points = trend.map((t, i) => ({
    x: pad + i * step,
    y: height - pad - (t.open / maxOpen) * (height - pad * 2),
  }));
  const line = points
    .map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`)
    .join(" ");
  const area = `${line} L${points[points.length - 1].x.toFixed(1)},${height - pad} L${pad},${height - pad} Z`;

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        role="img"
        aria-label="Open findings trend over the last 14 days"
      >
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(179,14,20,0.35)" />
            <stop offset="100%" stopColor="rgba(179,14,20,0.02)" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((frac) => (
          <line
            key={frac}
            x1={pad}
            x2={width - pad}
            y1={height - pad - frac * (height - pad * 2)}
            y2={height - pad - frac * (height - pad * 2)}
            stroke="#1a1a1a"
            strokeDasharray="4 6"
          />
        ))}
        <path d={area} fill="url(#trendFill)" />
        <path d={line} fill="none" stroke="#ff4d57" strokeWidth={2.5} />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={3} fill="#b30e14" />
        ))}
        <line
          x1={pad}
          x2={width - pad}
          y1={height - pad}
          y2={height - pad}
          stroke="#27272a"
        />
      </svg>
      <div className="mt-2 flex justify-between px-2 text-xs text-zinc-500">
        <span>{trend[0]?.date.slice(5)}</span>
        <span>{trend[Math.floor(trend.length / 2)]?.date.slice(5)}</span>
        <span>{trend[trend.length - 1]?.date.slice(5)}</span>
      </div>
      <div className="mt-4 flex items-center gap-6 text-xs text-zinc-400">
        <span className="flex items-center gap-2">
          <span className="h-2 w-4 rounded-full bg-[#ff4d57]" /> Open backlog
        </span>
        <span>
          {trend.reduce((sum, t) => sum + t.resolved, 0)} resolved in window
        </span>
      </div>
    </div>
  );
}
