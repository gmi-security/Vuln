"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill, ghostButtonClass, scrollAreaClass } from "@/components/ui";
import {
  connectorLabels,
  findingStatusClass,
  formatDateTime,
  scanStatusClass,
  severityClass,
} from "@/lib/format";
import type { Finding, Scan, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export default function VulnScanDetailPage({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [notFound, setNotFound] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/scans/${scanId}`, { cache: "no-store" });
      if (res.status === 404) {
        setNotFound(true);
        return;
      }
      const json = await res.json();
      setScan(json.scan ?? null);
      setFindings(json.findings ?? []);
    } catch {
      // keep last snapshot
    }
  }, [scanId]);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 3000);
    return () => clearInterval(timer);
  }, [load]);

  const subtitle = scan
    ? `${connectorLabels[scan.connector]} · ${scan.profile} · requested by ${scan.requestedBy}`
    : "Loading scan...";

  return (
    <VulnShell
      eyebrow="Scan detail"
      title={scan?.name ?? scanId}
      subtitle={subtitle}
      actions={
        <Link href="/scans" className={ghostButtonClass}>
          <ArrowLeft size={16} />
          All scans
        </Link>
      }
    >
      {notFound ? (
        <PanelCard eyebrow="Not found">
          <p className="text-zinc-400">
            This scan no longer exists.{" "}
            <Link href="/scans" className="text-[#ff4d57]">
              Back to scans
            </Link>
          </p>
        </PanelCard>
      ) : null}

      {scan ? (
        <>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <PanelCard eyebrow="Status">
              <div className="flex flex-wrap items-center gap-4">
                <Pill className={scanStatusClass[scan.status]}>
                  {scan.status}
                </Pill>
                <div className="flex flex-1 items-center gap-3">
                  <div className="h-2.5 min-w-32 flex-1 overflow-hidden rounded-full bg-[#101010]">
                    <div
                      className={[
                        "h-full rounded-full transition-all duration-700",
                        scan.status === "Completed"
                          ? "bg-emerald-500/70"
                          : "bg-[linear-gradient(90deg,#b30e14,#ff4d57)]",
                      ].join(" ")}
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                  <span className="text-sm text-zinc-400">
                    {scan.progress}%
                  </span>
                </div>
              </div>
              <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 text-sm">
                <div>
                  <dt className="text-zinc-500">Targets</dt>
                  <dd className="mt-1 text-zinc-200">
                    {scan.targets.join(", ")}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Hosts with findings</dt>
                  <dd className="mt-1 text-zinc-200">{scan.hostsScanned}</dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Started</dt>
                  <dd className="mt-1 text-zinc-200">
                    {formatDateTime(scan.startedAt)}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">Completed</dt>
                  <dd className="mt-1 text-zinc-200">
                    {formatDateTime(scan.completedAt)}
                  </dd>
                </div>
              </dl>
            </PanelCard>

            <PanelCard eyebrow="Findings by severity">
              <div className="grid grid-cols-5 gap-3">
                {SEVERITIES.map((severity) => (
                  <div
                    key={severity}
                    className="rounded-2xl border border-zinc-900 bg-[#090909] p-4 text-center"
                  >
                    <div className="text-3xl font-semibold text-white">
                      {scan.severityCounts[severity] ?? 0}
                    </div>
                    <div className="mt-2">
                      <Pill className={severityClass[severity]}>
                        {severity}
                      </Pill>
                    </div>
                  </div>
                ))}
              </div>
            </PanelCard>
          </div>

          <PanelCard
            eyebrow="Findings"
            description={
              scan.status === "Running" || scan.status === "Paused"
                ? "Findings appear when the scan completes"
                : `${findings.length} findings from this scan`
            }
          >
            <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
              <div className="grid grid-cols-[130px_1.8fr_1fr_100px_90px_140px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
                <div>CVE</div>
                <div>Finding</div>
                <div>Asset</div>
                <div>CVSS</div>
                <div>Severity</div>
                <div>Status</div>
              </div>
              <div className={`max-h-[560px] ${scrollAreaClass}`}>
                {findings.map((finding) => (
                  <Link
                    key={finding.id}
                    href={`/findings?focus=${finding.id}`}
                    className="grid grid-cols-[130px_1.8fr_1fr_100px_90px_140px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 transition last:border-b-0 hover:bg-[#0a0a0a]"
                  >
                    <div className="text-sm font-medium text-[#ff4d57]">
                      {finding.cve}
                    </div>
                    <div className="min-w-0">
                      <div className="truncate font-medium text-white">
                        {finding.title}
                      </div>
                      <div className="mt-1 text-xs text-zinc-500">
                        {finding.category} · {finding.port}
                      </div>
                    </div>
                    <div className="truncate text-sm text-zinc-300">
                      {finding.asset}
                    </div>
                    <div className="text-sm text-zinc-300">
                      {finding.cvss > 0 ? finding.cvss.toFixed(1) : "—"}
                    </div>
                    <div>
                      <Pill className={severityClass[finding.severity]}>
                        {finding.severity}
                      </Pill>
                    </div>
                    <div>
                      <Pill className={findingStatusClass[finding.status]}>
                        {finding.status}
                      </Pill>
                    </div>
                  </Link>
                ))}
                {findings.length === 0 ? (
                  <div className="px-5 py-12 text-center text-sm text-zinc-500">
                    No findings recorded for this scan yet.
                  </div>
                ) : null}
              </div>
            </div>
          </PanelCard>
        </>
      ) : null}
    </VulnShell>
  );
}
