"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Play } from "lucide-react";
import {
  IconAlertTriangle,
  IconBug,
  IconGauge,
  IconRadar,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill, StatCard, primaryButtonClass } from "@/components/ui";
import {
  compositeColor,
  connectorLabels,
  formatDateTime,
  scanStatusClass,
  severityBarColor,
  severityClass,
} from "@/lib/format";
import type { QuantifyMetrics, Scan, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export default function VulnDashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [metrics, setMetrics] = useState<QuantifyMetrics | null>(null);
  const [dbStatus, setDbStatus] = useState<{ reachable: boolean | null; error: string | null }>({
    reachable: null,
    error: null,
  });

  const load = useCallback(async () => {
    try {
      const [scansRes, metricsRes] = await Promise.all([
        fetch("/api/scans", { cache: "no-store" }),
        fetch("/api/metrics", { cache: "no-store" }),
      ]);
      if (!scansRes.ok || !metricsRes.ok) return; // keep last good state on server errors
      const scansJson = await scansRes.json();
      const metricsJson = await metricsRes.json();
      if (scansJson.scans) setScans(scansJson.scans);
      if (metricsJson.metrics) setMetrics(metricsJson.metrics);
    } catch {
      // keep the last good snapshot on transient errors
    }
  }, []);

  // Check DB health once on mount to surface connection errors early.
  useEffect(() => {
    void fetch("/api/health", { cache: "no-store" })
      .then((r) => r.json())
      .then((j) => {
        setDbStatus({
          reachable: j.persistence?.dbReachable ?? null,
          error: j.persistence?.dbError ?? null,
        });
      })
      .catch(() => setDbStatus({ reachable: false, error: "Health check failed." }));
  }, []);

  const running = scans.filter(
    (s) => s.status === "Running" || s.status === "Paused",
  );

  // Poll fast when scans are active (10s), slow when idle (60s).
  // Interval resets whenever running-scan count changes.
  useEffect(() => {
    void load();
    const interval = running.length > 0 ? 10_000 : 60_000;
    const timer = setInterval(() => void load(), interval);
    return () => clearInterval(timer);
  }, [load, running.length]);

  const recentScans = scans.slice(0, 6);
  const maxSeverity = Math.max(
    1,
    ...SEVERITIES.map((s) => metrics?.severityCounts[s] ?? 0),
  );

  const hasData = metrics !== null && metrics.totalOpen > 0;

  return (
    <VulnShell
      eyebrow="Dashboard"
      title="Vulnerability operations"
      subtitle="Live posture across Nessus, Vulners, and CrowdStrike Spotlight — open exposure, active scans, and where remediation effort should land next."
      actions={
        <Link href="/scans?new=1" className={primaryButtonClass}>
          <Play size={16} />
          Start scan
        </Link>
      }
    >
      {dbStatus.reachable === false ? (
        <div className="rounded-2xl border border-amber-900/60 bg-amber-950/30 px-5 py-4 text-sm">
          <span className="font-semibold text-amber-300">⚠ Database not connected</span>
          <span className="ml-2 text-amber-400/80">
            {dbStatus.error ?? "DATABASE_URL may be missing or unreachable."}
          </span>
          <span className="ml-2 text-amber-600">
            All sync data will be lost on redeploy until this is fixed. Check DATABASE_URL in your DigitalOcean environment variables.
          </span>
        </div>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Open findings"
          value={metrics ? metrics.totalOpen : "—"}
          sublabel={`${metrics?.exploitableOpen ?? 0} with known exploit`}
          icon={<IconBug size={26} />}
        />
        <StatCard
          label="Critical open"
          value={metrics ? metrics.severityCounts.Critical : "—"}
          sublabel={`${metrics?.severityCounts.High ?? 0} high severity open`}
          icon={<IconAlertTriangle size={26} />}
        />
        <StatCard
          label="Active scans"
          value={running.length}
          sublabel={`${scans.length} scans total`}
          icon={<IconRadar size={26} />}
        />
        <StatCard
          label="Composite risk"
          value={
            metrics ? (
              <span style={{ color: compositeColor(metrics.composite.score) }}>
                {metrics.composite.score}
              </span>
            ) : (
              "—"
            )
          }
          sublabel={
            metrics
              ? `${metrics.composite.band} · exposure ${metrics.exposureScore}`
              : ""
          }
          icon={<IconGauge size={26} />}
        />
      </div>

      {metrics !== null && !hasData ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.06)] px-6 py-5">
          <div className="text-sm font-semibold text-white">No findings yet</div>
          <p className="mt-1 text-sm text-zinc-400">
            The console is live but has no scan data yet. Go to{" "}
            <Link href="/connectors" className="text-[#ff4d57] hover:text-white transition">
              Connectors
            </Link>{" "}
            and click <strong className="text-zinc-200">Sync now</strong> on CrowdStrike Devices and CrowdStrike Spotlight to import your first dataset.
          </p>
        </div>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <PanelCard
          eyebrow="Recent scans"
          description="Latest scan activity across all connectors"
          actions={
            <Link
              href="/scans"
              className="text-sm text-[#ff4d57] transition hover:text-white"
            >
              View all →
            </Link>
          }
        >
          <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
            <div className="grid grid-cols-[1.6fr_120px_130px_110px_150px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
              <div>Scan</div>
              <div>Connector</div>
              <div>Status</div>
              <div>Findings</div>
              <div>Started</div>
            </div>
            {recentScans.map((scan) => (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="grid grid-cols-[1.6fr_120px_130px_110px_150px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 transition last:border-b-0 hover:bg-[#0a0a0a]"
              >
                <div>
                  <div className="font-medium text-white">{scan.name}</div>
                  <div className="mt-1 text-xs text-zinc-500">
                    {scan.targets.join(", ")}
                  </div>
                </div>
                <div className="text-sm text-zinc-300">
                  {connectorLabels[scan.connector]}
                </div>
                <div>
                  <Pill className={scanStatusClass[scan.status]}>
                    {scan.status === "Running"
                      ? `${scan.progress}%`
                      : scan.status}
                  </Pill>
                </div>
                <div className="text-sm text-zinc-300">
                  {scan.status === "Completed" ? scan.findingsCount : "—"}
                </div>
                <div className="text-sm text-zinc-400">
                  {formatDateTime(scan.startedAt)}
                </div>
              </Link>
            ))}
            {recentScans.length === 0 ? (
              <div className="px-5 py-10 text-center text-sm text-zinc-500">
                No scans yet — start one to populate the console.
              </div>
            ) : null}
          </div>
        </PanelCard>

        <div className="space-y-5">
          <PanelCard
            eyebrow="Open by severity"
            description="Current open findings"
          >
            <div className="space-y-3">
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
          </PanelCard>

          <PanelCard
            eyebrow="Top risk assets"
            description="Severity-weighted, exploit-boosted"
          >
            <div className="space-y-2">
              {(metrics?.assetRisk ?? []).slice(0, 5).map((asset) => (
                <div
                  key={asset.asset}
                  className="flex items-center justify-between gap-3 rounded-2xl border border-zinc-900 bg-[#090909] px-4 py-3"
                >
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-white">
                      {asset.asset}
                    </div>
                    <div className="mt-1 text-xs text-zinc-500">
                      {asset.open} open
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Pill className={severityClass[asset.worst]}>
                      {asset.worst}
                    </Pill>
                    <span className="text-lg font-semibold text-white">
                      {asset.score}
                    </span>
                  </div>
                </div>
              ))}
              {(metrics?.assetRisk ?? []).length === 0 ? (
                <div className="py-6 text-center text-sm text-zinc-500">
                  No open findings.
                </div>
              ) : null}
            </div>
          </PanelCard>
        </div>
      </div>

      <PanelCard
        eyebrow="By client"
        description="Open exposure per company"
        actions={
          <Link
            href="/companies"
            className="text-sm text-[#ff4d57] transition hover:text-white"
          >
            All companies →
          </Link>
        }
      >
        <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
          <div className="grid grid-cols-[1.6fr_110px_110px_150px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
            <div>Company</div>
            <div>Open</div>
            <div>Critical</div>
            <div>Exposure</div>
          </div>
          {(metrics?.companyBreakdown ?? []).map((c) => (
            <Link
              key={c.companyId}
              href={`/companies/${c.companyId}`}
              className="grid grid-cols-[1.6fr_110px_110px_150px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 transition last:border-b-0 hover:bg-[#0a0a0a]"
            >
              <div className="font-medium text-white">{c.companyName}</div>
              <div className="text-sm text-zinc-300">{c.open}</div>
              <div className="text-sm text-[#ff4d57]">{c.critical}</div>
              <div className="flex items-center gap-3">
                <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-[#101010]">
                  <div
                    className="h-full rounded-full bg-[linear-gradient(90deg,#b30e14,#ff4d57)]"
                    style={{ width: `${c.exposureScore}%` }}
                  />
                </div>
                <span className="w-8 text-right text-sm font-semibold text-white">
                  {c.exposureScore}
                </span>
              </div>
            </Link>
          ))}
          {(metrics?.companyBreakdown ?? []).length === 0 ? (
            <div className="px-5 py-10 text-center text-sm text-zinc-500">
              No client findings yet.
            </div>
          ) : null}
        </div>
      </PanelCard>
    </VulnShell>
  );
}
