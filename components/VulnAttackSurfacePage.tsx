"use client";

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCcw, Globe, Server, KeyRound, Bug, Radar } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { StatCard, ghostButtonClass, primaryButtonClass } from "@/components/ui";

type SurfaceCategory =
  | "Exposed Services"
  | "Subdomains & DNS"
  | "Leaked Credentials"
  | "Web Vulnerabilities"
  | "Threat Intel"
  | "Info Disclosure";

type SurfaceItem = {
  id: string;
  asset: string;
  category: SurfaceCategory;
  rawCategory: string;
  severity: string;
  source: "artemis" | "spiderfoot";
  title: string;
  description: string;
};

type CompanySurface = {
  companyId: string;
  companyName: string;
  total: number;
  exposedAssets: number;
  byCategory: Record<SurfaceCategory, number>;
  items: SurfaceItem[];
};

type SurfaceResult = {
  summary: {
    total: number;
    companies: number;
    exposedAssets: number;
    byCategory: Record<SurfaceCategory, number>;
    bySource: { artemis: number; spiderfoot: number };
  };
  companies: CompanySurface[];
};

const CATEGORIES: SurfaceCategory[] = [
  "Exposed Services",
  "Subdomains & DNS",
  "Leaked Credentials",
  "Web Vulnerabilities",
  "Threat Intel",
  "Info Disclosure",
];

const categoryClass: Record<SurfaceCategory, string> = {
  "Leaked Credentials": "text-[#ff4d57] border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.12)]",
  "Web Vulnerabilities": "text-orange-300 border-orange-900/60 bg-[rgba(245,110,35,0.10)]",
  "Exposed Services": "text-amber-300 border-amber-900/60 bg-[rgba(245,166,35,0.10)]",
  "Threat Intel": "text-[#ff8f96] border-[rgba(179,14,20,0.35)] bg-[rgba(179,14,20,0.08)]",
  "Subdomains & DNS": "text-sky-300 border-sky-900/60 bg-[rgba(74,163,255,0.10)]",
  "Info Disclosure": "text-zinc-300 border-zinc-800 bg-zinc-950",
};

const sevDot: Record<string, string> = {
  Critical: "bg-[#ff4d57]",
  High: "bg-orange-400",
  Medium: "bg-amber-300",
  Low: "bg-sky-400",
  Info: "bg-zinc-600",
};

export default function VulnAttackSurfacePage() {
  const [data, setData] = useState<SurfaceResult | null>(null);
  const [pivoting, setPivoting] = useState(false);
  const [pivotMsg, setPivotMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/attack-surface", { cache: "no-store" });
      setData((await res.json()).surface ?? null);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function pivot() {
    if (pivoting) return;
    setPivoting(true);
    setPivotMsg(null);
    try {
      const res = await fetch("/api/attack-surface/pivot", { method: "POST" });
      const r = (await res.json()).result;
      setPivotMsg(
        r
          ? `Queued ${r.scansLaunched} Nessus scan(s) across ${r.companies} client(s) — ${r.assetsQueued} exposed asset(s), ${r.skipped} already covered.`
          : "Pivot failed.",
      );
    } catch {
      setPivotMsg("Pivot failed.");
    } finally {
      setPivoting(false);
    }
  }

  const sum = data?.summary;

  return (
    <VulnShell
      eyebrow="Attack Surface"
      title="External attack surface"
      subtitle="What an attacker sees from the outside — OSINT & attack-surface exposure per client from Artemis + SpiderFoot: exposed services, subdomains, leaked credentials, and web weaknesses. Deliberately separate from CVE findings."
      actions={
        <>
          <button
            onClick={() => void pivot()}
            disabled={pivoting}
            className={`${primaryButtonClass} disabled:opacity-50`}
            title="Queue targeted Nessus scans of the assets OSINT flagged as exposed"
          >
            <Radar size={16} />
            {pivoting ? "Queuing…" : "Confirm with Nessus"}
          </button>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </>
      }
    >
      {pivotMsg ? (
        <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/40 px-5 py-3 text-sm text-emerald-300">
          {pivotMsg}
        </div>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Total exposures"
          value={sum ? sum.total : "—"}
          sublabel={sum ? `Artemis ${sum.bySource.artemis} · SpiderFoot ${sum.bySource.spiderfoot}` : "OSINT signals"}
          icon={<Globe size={26} />}
        />
        <StatCard
          label="Exposed assets"
          value={sum ? sum.exposedAssets : "—"}
          sublabel="Distinct hosts / domains"
          icon={<Server size={26} />}
        />
        <StatCard
          label="Leaked credentials"
          value={sum ? sum.byCategory["Leaked Credentials"] : "—"}
          sublabel="Compromised / breached"
          icon={<KeyRound size={26} />}
        />
        <StatCard
          label="Web weaknesses"
          value={sum ? sum.byCategory["Web Vulnerabilities"] : "—"}
          sublabel="Misconfig, injection, panels"
          icon={<Bug size={26} />}
        />
      </div>

      {sum && sum.total === 0 ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-8 text-center text-sm text-zinc-500">
          No OSINT data yet. Run the <strong>OSINT sweep</strong> on the Connectors
          page, then <strong>Sync</strong> Artemis / SpiderFoot — their findings
          land here as attack-surface exposure.
        </div>
      ) : null}

      {(data?.companies ?? []).map((co) => (
        <div
          key={co.companyId}
          className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="text-lg font-semibold text-white">{co.companyName}</div>
            <div className="text-xs text-zinc-500">
              {co.total} exposure{co.total === 1 ? "" : "s"} · {co.exposedAssets}{" "}
              asset{co.exposedAssets === 1 ? "" : "s"}
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {CATEGORIES.filter((c) => co.byCategory[c] > 0).map((c) => (
              <span
                key={c}
                className={`rounded-full border px-3 py-1 text-xs ${categoryClass[c]}`}
              >
                {c} · {co.byCategory[c]}
              </span>
            ))}
          </div>

          <div className="mt-4 max-h-80 space-y-2 overflow-y-auto rounded-xl border border-zinc-900 bg-[#040404] p-3">
            {co.items.map((it) => (
              <div key={it.id} className="flex items-start gap-3 border-b border-zinc-900/60 pb-2 last:border-b-0 last:pb-0">
                <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${sevDot[it.severity] ?? "bg-zinc-600"}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-white">{it.title}</span>
                    <span className="text-[11px] text-zinc-600">{it.source === "spiderfoot" ? "SpiderFoot" : "Artemis"} · {it.rawCategory}</span>
                  </div>
                  <div className="text-xs text-zinc-500">on {it.asset}</div>
                </div>
                <span
                  className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] ${categoryClass[it.category]}`}
                >
                  {it.category}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </VulnShell>
  );
}
