"use client";

import { useEffect, useState } from "react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill } from "@/components/ui";

// Fixed display zone: GMT-7, no DST, matching how this team actually thinks
// about scan times regardless of what timezone a given Nessus scan's own
// schedule happens to be stored in (America/Phoenix never observes DST, so
// it's always exactly GMT-7, unlike e.g. America/Denver).
const DISPLAY_ZONE = "America/Phoenix";

function fmt(iso: string | null): string {
  if (!iso) return "—";
  const formatted = new Date(iso).toLocaleString("en-US", {
    timeZone: DISPLAY_ZONE,
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
  return `${formatted} GMT-7`;
}

type ScheduleEntry = {
  nessusScanId: number;
  scanName: string;
  enabled: boolean;
  rrules: string | null;
  timezone: string | null;
  lastOccurrence: string | null;
  nextOccurrence: string | null;
  offsetLastTriggered: string | null;
  offsetNextTrigger: string | null;
};

type ScheduleCompany = {
  companyId: string;
  companyName: string;
  scans: ScheduleEntry[];
};

type ScheduleMatrix = {
  generatedAt: string;
  bridgeConfigured: boolean;
  autoSync: { enabled: boolean; intervalHours: number; lastRunAt: string | null };
  companies: ScheduleCompany[];
};

export default function VulnSchedulePage() {
  const [data, setData] = useState<ScheduleMatrix | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = () =>
      fetch("/api/schedule-matrix", { cache: "no-store" })
        .then((res) => res.json())
        .then((json) => {
          setData(json);
          setError(null);
        })
        .catch(() => setError("Could not load the schedule."));
    void load();
    const timer = setInterval(load, 30_000);
    return () => clearInterval(timer);
  }, []);

  const rows = data?.companies.flatMap((company) =>
    company.scans.map((scan) => ({ company, scan })),
  ) ?? [];

  return (
    <VulnShell
      eyebrow="Scheduling"
      title="Scan Schedule"
      subtitle="When each company's Nessus scan actually runs, and when its Vulners Bridge offset rescan is due or already ran — all times GMT-7."
    >
      <PanelCard
        eyebrow="Auto-sync"
        description="The general sync-all cadence — separate from the per-company Nessus offset below, and a second source of Vulners Bridge scans if enabled."
      >
        {data ? (
          <div className="flex flex-wrap items-center gap-3 text-sm text-zinc-300">
            <Pill className={data.autoSync.enabled ? "bg-emerald-500/15 text-emerald-300" : "bg-zinc-500/15 text-zinc-400"}>
              {data.autoSync.enabled ? "Enabled" : "Disabled"}
            </Pill>
            <span>Every {data.autoSync.intervalHours}h</span>
            <span className="text-zinc-500">Last run: {fmt(data.autoSync.lastRunAt)}</span>
            {!data.bridgeConfigured ? (
              <Pill className="bg-amber-500/15 text-amber-300">Vulners Bridge not configured</Pill>
            ) : null}
          </div>
        ) : (
          <p className="text-zinc-500">{error ?? "Loading…"}</p>
        )}
      </PanelCard>

      <PanelCard
        eyebrow="Nessus → Vulners Bridge offset"
        description="Each row's Vulners Bridge rescan is deliberately offset 1 hour after that company's own Nessus schedule, so the two active scanners never hit the same hosts at once."
      >
        {rows.length === 0 ? (
          <p className="text-zinc-500">{data ? "No companies with a recurring Nessus scan on record yet." : (error ?? "Loading…")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs uppercase tracking-wide text-zinc-500">
                  <th className="py-2 pr-4">Company</th>
                  <th className="py-2 pr-4">Nessus Scan</th>
                  <th className="py-2 pr-4">Nessus Last Run</th>
                  <th className="py-2 pr-4">Nessus Next Run</th>
                  <th className="py-2 pr-4">Bridge Last Triggered</th>
                  <th className="py-2 pr-4">Bridge Next Trigger</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ company, scan }) => (
                  <tr key={`${company.companyId}:${scan.nessusScanId}`} className="border-b border-zinc-900">
                    <td className="py-2 pr-4 text-zinc-200">{company.companyName}</td>
                    <td className="py-2 pr-4 text-zinc-400">
                      {scan.scanName}
                      {!scan.enabled ? (
                        <Pill className="ml-2 bg-zinc-500/15 text-zinc-400">disabled</Pill>
                      ) : null}
                    </td>
                    <td className="py-2 pr-4 text-zinc-400">{fmt(scan.lastOccurrence)}</td>
                    <td className="py-2 pr-4 text-zinc-400">{fmt(scan.nextOccurrence)}</td>
                    <td className="py-2 pr-4 text-zinc-400">{fmt(scan.offsetLastTriggered)}</td>
                    <td className="py-2 pr-4 text-zinc-200">{fmt(scan.offsetNextTrigger)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PanelCard>
    </VulnShell>
  );
}
