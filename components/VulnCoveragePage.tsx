"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Radar, RefreshCcw } from "lucide-react";
import {
  IconAlertTriangle,
  IconDatabaseCog,
  IconEye,
  IconRadar2,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import {
  PanelCard,
  StatCard,
  ghostButtonClass,
  primaryButtonClass,
  selectClass,
} from "@/components/ui";
import { exposureClass, riskColor } from "@/lib/format";
import type { Company } from "@/lib/types";

type CoverageRow = {
  identifier: string;
  companyName: string;
  exposure: string | null;
  criticality: string | null;
  owner: string | null;
  source: string | null;
  openFindings: number;
  worstRisk: number;
};

type Coverage = {
  summary: {
    known: number;
    scanned: number;
    matched: number;
    knownNotScanned: number;
    scannedNotKnown: number;
  };
  matched: CoverageRow[];
  knownNotScanned: CoverageRow[];
  scannedNotKnown: CoverageRow[];
};

export default function VulnCoveragePage() {
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [companies, setCompanies] = useState<Company[]>([]);
  const [companyFilter, setCompanyFilter] = useState("All");
  const [autoScan, setAutoScan] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);
  const [toggleError, setToggleError] = useState<string | null>(null);
  // Monotonic request id — a slow older response must never overwrite a newer one.
  const loadSeq = useRef(0);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    const q = companyFilter === "All" ? "" : `?companyId=${companyFilter}`;
    try {
      const res = await fetch(`/api/assets/coverage${q}`, { cache: "no-store" });
      const json = await res.json();
      if (seq !== loadSeq.current) return; // superseded by a newer request
      setCoverage(json.coverage ?? null);
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
    void fetch("/api/settings", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setAutoScan(Boolean(json.settings?.autoScanNewAssets)))
      .catch(() => undefined);
  }, []);

  async function toggleAutoScan() {
    const next = !autoScan;
    setAutoScan(next);
    setToggleError(null);
    try {
      const res = await fetch("/api/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ autoScanNewAssets: next }),
      });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        setAutoScan(!next); // roll back the optimistic flip
        setToggleError(
          json.error ?? `Failed to save setting (HTTP ${res.status}).`,
        );
        return;
      }
      // Turning it on sweeps the current gap immediately.
      if (next) await runAutoScan();
    } catch {
      setAutoScan(!next); // roll back the optimistic flip
      setToggleError("Failed to reach the API — setting not saved.");
    }
  }

  async function runAutoScan() {
    setScanning(true);
    setScanMsg(null);
    try {
      const res = await fetch("/api/coverage/autoscan", { method: "POST" });
      const json = await res.json();
      const r = json.result;
      setScanMsg(
        r.assetsQueued > 0
          ? `Launched ${r.scansLaunched} scan${r.scansLaunched === 1 ? "" : "s"} across ${r.companies} customer${r.companies === 1 ? "" : "s"}, covering ${r.assetsQueued} new asset${r.assetsQueued === 1 ? "" : "s"}.`
          : "No unscanned assets — coverage is complete.",
      );
      await load();
    } catch {
      setScanMsg("Failed to launch auto-scan.");
    } finally {
      setScanning(false);
    }
  }

  const s = coverage?.summary;
  const coveragePct =
    s && s.known > 0 ? Math.round((s.matched / s.known) * 100) : -1;

  return (
    <VulnShell
      eyebrow="Coverage"
      title="Asset coverage"
      subtitle="Known assets (Tidal inventory) vs scanned assets (seen in results). Surfaces inventory we haven't scanned and scanned hosts that aren't in inventory — matched per customer."
      actions={
        <>
          <button
            onClick={() => void runAutoScan()}
            disabled={scanning}
            className={`${primaryButtonClass} disabled:opacity-50`}
          >
            <Radar size={16} />
            {scanning ? "Scanning..." : "Scan gaps now"}
          </button>
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
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[rgba(179,14,20,0.16)] bg-[#080808] px-5 py-4">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium text-white">
            <Radar size={16} className="text-[#b30e14]" />
            Auto-scan new assets
          </div>
          <p className="mt-1 text-xs text-zinc-500">
            Automatically launch a scan whenever a known asset has no coverage —
            on the diff and after each Tidal sync.
          </p>
          {toggleError ? (
            <p className="mt-1 text-xs text-[#ff4d57]">{toggleError}</p>
          ) : null}
        </div>
        <button
          role="switch"
          aria-checked={autoScan}
          onClick={() => void toggleAutoScan()}
          className={[
            "relative h-7 w-12 rounded-full border transition",
            autoScan
              ? "border-[rgba(179,14,20,0.5)] bg-[rgba(179,14,20,0.4)]"
              : "border-zinc-700 bg-zinc-800",
          ].join(" ")}
        >
          <span
            className={[
              "absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all",
              autoScan ? "left-[26px]" : "left-0.5",
            ].join(" ")}
          />
        </button>
      </div>

      {scanMsg ? (
        <div className="rounded-2xl border border-emerald-900/60 bg-emerald-950/40 px-5 py-3 text-sm text-emerald-300">
          {scanMsg}
        </div>
      ) : null}
      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Known assets"
          value={s ? s.known : "—"}
          sublabel="In Tidal / manual inventory"
          icon={<IconDatabaseCog size={26} />}
        />
        <StatCard
          label="Scan coverage"
          value={coveragePct >= 0 ? `${coveragePct}%` : "—"}
          sublabel={s ? `${s.matched} of ${s.known} known assets scanned` : ""}
          icon={<IconRadar2 size={26} />}
        />
        <StatCard
          label="Known, not scanned"
          value={s ? s.knownNotScanned : "—"}
          sublabel="Inventory blind spots — scan these"
          icon={<IconAlertTriangle size={26} />}
        />
        <StatCard
          label="Scanned, not in inventory"
          value={s ? s.scannedNotKnown : "—"}
          sublabel="Shadow / unmanaged assets"
          icon={<IconEye size={26} />}
        />
      </div>

      <PanelCard
        eyebrow="Known, not scanned"
        description="Assets in the inventory with no scan findings — coverage gaps to close"
      >
        <CoverageTable
          rows={coverage?.knownNotScanned ?? []}
          kind="known"
          empty="Every known asset has been scanned."
        />
      </PanelCard>

      <PanelCard
        eyebrow="Scanned, not in inventory"
        description="Assets seen in scan results but absent from the inventory — reconcile in Tidal or investigate as shadow IT"
      >
        <CoverageTable
          rows={coverage?.scannedNotKnown ?? []}
          kind="shadow"
          empty="Every scanned asset is in the inventory."
        />
      </PanelCard>

      <PanelCard
        eyebrow="Matched"
        description="Assets present in both inventory and scan results"
      >
        <CoverageTable
          rows={coverage?.matched ?? []}
          kind="matched"
          empty="No matched assets yet."
        />
      </PanelCard>
    </VulnShell>
  );
}

function CoverageTable({
  rows,
  kind,
  empty,
}: {
  rows: CoverageRow[];
  kind: "known" | "shadow" | "matched";
  empty: string;
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-zinc-800 bg-[#080808] px-5 py-8 text-center text-sm text-zinc-500">
        {empty}
      </div>
    );
  }
  const showContext = kind !== "shadow";
  return (
    <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
      <div className="grid grid-cols-[1.7fr_1.1fr_1fr_120px_110px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
        <div>Asset</div>
        <div>Client</div>
        <div>{showContext ? "Exposure · Criticality" : "Status"}</div>
        <div>Open</div>
        <div>Worst risk</div>
      </div>
      <div className="max-h-[420px] overflow-y-auto">
        {rows.map((r, i) => (
          <div
            key={`${r.companyName}-${r.identifier}-${i}`}
            className="grid grid-cols-[1.7fr_1.1fr_1fr_120px_110px] items-center gap-4 border-b border-zinc-900/70 px-5 py-3 last:border-b-0"
          >
            <div className="truncate font-medium text-white">{r.identifier}</div>
            <div className="truncate text-sm text-zinc-400">{r.companyName}</div>
            <div className="text-sm">
              {showContext && r.exposure ? (
                <span className={exposureClass[r.exposure] ?? "text-zinc-300"}>
                  {r.exposure} · {r.criticality}
                </span>
              ) : kind === "shadow" ? (
                <span className="text-amber-300">Not in inventory</span>
              ) : (
                <span className="text-zinc-500">—</span>
              )}
            </div>
            <div className="text-sm text-zinc-300">
              {kind === "known" ? (
                <span className="text-zinc-600">not scanned</span>
              ) : (
                r.openFindings
              )}
            </div>
            <div>
              {kind === "known" ? (
                <span className="text-sm text-zinc-600">—</span>
              ) : (
                <span
                  className="text-lg font-semibold"
                  style={{ color: riskColor(r.worstRisk) }}
                >
                  {r.worstRisk}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
