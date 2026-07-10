"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCcw } from "lucide-react";
import {
  IconBomb,
  IconCrown,
  IconDoorEnter,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill, StatCard, ghostButtonClass, selectClass } from "@/components/ui";
import { compositeColor, exposureClass, riskColor } from "@/lib/format";
import type { AttackEntry, AttackPathResult, Company } from "@/lib/types";

const roleClass: Record<string, string> = {
  entry: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
  pivot: "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  target: "bg-[rgba(167,139,250,0.12)] text-violet-300 border border-violet-900/60",
};

export default function VulnAttackPathsPage() {
  const [data, setData] = useState<AttackPathResult | null>(null);
  const [companies, setCompanies] = useState<Company[]>([]);
  const [companyFilter, setCompanyFilter] = useState("All");
  // Monotonic request id — a slow older response must never overwrite a newer one.
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    const q = companyFilter === "All" ? "" : `?companyId=${companyFilter}`;
    try {
      const res = await fetch(`/api/attack-paths${q}`, { cache: "no-store" });
      const json = await res.json();
      if (seq !== loadSeq.current) return; // superseded by a newer request
      setData(json.attackPaths ?? null);
    } catch {
      // keep last snapshot
    }
  }, [companyFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    void fetch("/api/companies", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setCompanies(json.companies ?? []))
      .catch(() => undefined);
  }, []);

  const s = data?.summary;

  return (
    <VulnShell
      eyebrow="Attack Paths"
      title="Blast radius"
      subtitle="Full kill chains: each exploitable internet-facing entry, traced hop-by-hop across lateral (same-subnet) and perimeter pivots to the highest-value crown jewel it can reach. Reachability is modeled from exposure, criticality, and /24 adjacency — connect firewall/identity data for observed topology."
      actions={
        <>
          <select
            value={companyFilter}
            onChange={(e) => setCompanyFilter(e.target.value)}
            className={selectClass}
          >
            <option value="All">All companies</option>
            {companies.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </>
      }
    >
      <div className="grid gap-5 md:grid-cols-3">
        <StatCard
          label="Entry points"
          value={s ? s.entryPoints : "—"}
          sublabel="Internet-facing & exploitable"
          icon={<IconDoorEnter size={26} />}
        />
        <StatCard
          label="Crown jewels at risk"
          value={s ? s.crownJewelsAtRisk : "—"}
          sublabel="Reachable from an entry point"
          icon={<IconCrown size={26} />}
        />
        <StatCard
          label="Max blast radius"
          value={s ? s.maxBlast : "—"}
          sublabel="Worst single entry point, 0–100"
          icon={<IconBomb size={26} />}
        />
      </div>

      {(data?.entries ?? []).length === 0 ? (
        <PanelCard eyebrow="Attack paths">
          <div className="px-5 py-12 text-center text-sm text-zinc-500">
            No internet-facing exploitable entry points found. As inventory
            (exposure/criticality) fills in, real paths surface here.
          </div>
        </PanelCard>
      ) : (
        (data?.entries ?? []).map((entry) => (
          <AttackPathCard key={entry.id} entry={entry} />
        ))
      )}
    </VulnShell>
  );
}

function AttackPathCard({ entry }: { entry: AttackEntry }) {
  return (
    <PanelCard
      eyebrow={entry.companyName}
      actions={
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">
              Entry ease
            </div>
            <div
              className="text-lg font-semibold"
              style={{ color: riskColor(entry.entryScore) }}
            >
              {entry.entryScore}
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">
              Blast
            </div>
            <div
              className="text-2xl font-semibold"
              style={{ color: compositeColor(entry.blastScore) }}
            >
              {entry.blastScore}
            </div>
          </div>
        </div>
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <span className="font-medium text-white">{entry.asset}</span>
        <span className={exposureClass[entry.exposure] ?? "text-zinc-400"}>
          {entry.exposure} · {entry.criticality}
        </span>
        {entry.kev ? (
          <Pill className="border border-[rgba(179,14,20,0.55)] bg-[rgba(179,14,20,0.16)] text-[#ff4d57]">
            KEV
          </Pill>
        ) : null}
        <span className="text-zinc-500">
          {entry.hops} hop{entry.hops === 1 ? "" : "s"} to{" "}
          {entry.targetCriticality ?? "target"} · reaches {entry.reachable} asset
          {entry.reachable === 1 ? "" : "s"} · {entry.crownJewelsReached} crown
          jewel{entry.crownJewelsReached === 1 ? "" : "s"}
        </span>
      </div>

      {/* Multi-hop kill-chain with the move technique labelled per connector. */}
      <div className="flex flex-col gap-2 lg:flex-row lg:items-stretch lg:overflow-x-auto lg:pb-1">
        {entry.path.map((hop, i) => (
          <React.Fragment key={`${hop.asset}-${i}`}>
            <div className="min-w-[190px] flex-1 rounded-2xl border border-zinc-900 bg-[#090909] p-4">
              <div className="flex items-center justify-between gap-2">
                <Pill className={roleClass[hop.role]}>
                  {hop.role === "entry"
                    ? "Entry"
                    : hop.role === "pivot"
                      ? `Pivot ${i}`
                      : "Objective"}
                </Pill>
                {hop.realRisk > 0 ? (
                  <span
                    className="text-sm font-semibold"
                    style={{ color: riskColor(hop.realRisk) }}
                  >
                    {hop.realRisk}
                  </span>
                ) : null}
              </div>
              <div className="mt-3 truncate font-medium text-white" title={hop.asset}>
                {hop.asset}
              </div>
              <div
                className={`mt-1 text-xs ${exposureClass[hop.exposure] ?? "text-zinc-500"}`}
              >
                {hop.exposure} · {hop.criticality}
              </div>
              {hop.cve ? (
                <div className="mt-3 flex items-center gap-2 text-xs text-zinc-500">
                  <span className="text-[#ff8f96]">{hop.cve}</span>
                  {hop.kev ? (
                    <span className="rounded-full border border-[rgba(179,14,20,0.5)] bg-[rgba(179,14,20,0.14)] px-1.5 py-0.5 text-[9px] uppercase tracking-[0.12em] text-[#ff4d57]">
                      KEV
                    </span>
                  ) : null}
                </div>
              ) : (
                <div className="mt-3 text-xs text-zinc-600">
                  {hop.reachableOnly
                    ? "reachable · no known exploit"
                    : hop.role === "target"
                      ? "high-value asset"
                      : "no open findings"}
                </div>
              )}
            </div>
            {i < entry.path.length - 1 ? (
              <div className="flex flex-col items-center justify-center gap-1 text-zinc-600 lg:px-1">
                <span className="hidden lg:block">→</span>
                <span className="lg:hidden">↓</span>
                {entry.path[i + 1]?.via ? (
                  <span className="whitespace-nowrap rounded-full border border-zinc-800 bg-zinc-950 px-2 py-0.5 text-[9px] text-zinc-400">
                    {entry.path[i + 1].via}
                  </span>
                ) : null}
              </div>
            ) : null}
          </React.Fragment>
        ))}
      </div>
    </PanelCard>
  );
}
