"use client";

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCcw, ShieldCheck, AlarmClock, Timer, CheckCircle2 } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import RiskGauge from "@/components/RiskGauge";
import { KennaStatChip, ghostButtonClass } from "@/components/ui";

type SlaClientRow = {
  companyId: string;
  companyName: string;
  open: number;
  withinSla: number;
  dueSoon: number;
  breached: number;
  slaCompliance: number;
  mttrDays: number | null;
  resolved30: number;
  worstBreachSeverity: string | null;
};

type SlaResult = {
  overall: {
    open: number;
    withinSla: number;
    dueSoon: number;
    breached: number;
    slaCompliance: number;
    mttrDays: number | null;
    resolved30: number;
  };
  burndown: { date: string; open: number; resolved: number }[];
  slaPolicy: { severity: string; days: number }[];
  clients: SlaClientRow[];
};

function complianceColor(pct: number): string {
  if (pct >= 90) return "#10b981";
  if (pct >= 75) return "#f5a623";
  if (pct >= 50) return "#f97316";
  return "#ff4d57";
}

function Burndown({ data }: { data: { date: string; open: number; resolved: number }[] }) {
  if (data.length === 0) return null;
  const W = 720;
  const H = 160;
  const pad = 8;
  const maxOpen = Math.max(1, ...data.map((d) => d.open));
  const maxRes = Math.max(1, ...data.map((d) => d.resolved));
  const stepX = (W - pad * 2) / Math.max(1, data.length - 1);
  const x = (i: number) => pad + i * stepX;
  const yOpen = (v: number) => pad + (H - pad * 2) * (1 - v / maxOpen);

  const linePts = data.map((d, i) => `${x(i)},${yOpen(d.open)}`).join(" ");
  const areaPts = `${pad},${H - pad} ${linePts} ${x(data.length - 1)},${H - pad}`;

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[520px]" preserveAspectRatio="none" style={{ height: 180 }}>
        {/* resolved-per-day bars (bottom, subtle) */}
        {data.map((d, i) => {
          const bh = (H - pad * 2) * (d.resolved / maxRes) * 0.4;
          return (
            <rect
              key={i}
              x={x(i) - 3}
              y={H - pad - bh}
              width={6}
              height={bh}
              fill="rgba(16,185,129,0.35)"
              rx={1}
            />
          );
        })}
        {/* open backlog area + line */}
        <polygon points={areaPts} fill="rgba(179,14,20,0.12)" />
        <polyline points={linePts} fill="none" stroke="#ff4d57" strokeWidth={2} />
      </svg>
    </div>
  );
}

export default function VulnSlaPage() {
  const [data, setData] = useState<SlaResult | null>(null);
  // Drill-down target for the per-client table below -- selecting a client
  // doesn't refetch anything (the org-wide /api/sla response already
  // carries every client's row), it just reveals that client's section.
  // This is the first step toward relocating the ConnectWise ticket-cutting
  // review queue here: it'll mount in that conditional section once it's
  // moved from /reporting.
  const [companyId, setCompanyId] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/sla", { cache: "no-store" });
      setData((await res.json()).sla ?? null);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const o = data?.overall;
  const selected = data?.clients.find((c) => c.companyId === companyId) ?? null;

  return (
    <VulnShell
      eyebrow="Remediation SLA"
      title="Remediation SLA & burndown"
      subtitle="Are findings being fixed inside their remediation window, per client? Backlog burndown, SLA compliance, and mean-time-to-remediate — the operational health of the whole program."
      actions={
        <button onClick={() => void load()} className={ghostButtonClass}>
          <RefreshCcw size={16} className="text-zinc-400" />
          Refresh
        </button>
      }
    >
      <div className="flex flex-col items-center gap-6 rounded-[28px] border border-[rgba(179,14,20,0.16)] bg-[linear-gradient(180deg,#0b0b0b,#060606)] p-6 shadow-[0_12px_32px_rgba(10,1,2,0.3)] lg:flex-row lg:items-stretch">
        <div className="flex flex-col items-center justify-center gap-2 lg:border-r lg:border-zinc-900 lg:pr-6">
          <RiskGauge
            score={o ? o.slaCompliance : 0}
            color={o ? complianceColor(o.slaCompliance) : "#71717a"}
            label="SLA compliance"
            sublabel="open findings within window"
          />
        </div>
        <div className="grid flex-1 grid-cols-2 gap-3 sm:grid-cols-3">
          <KennaStatChip
            icon={<AlarmClock size={16} />}
            label="SLA breached"
            value={o ? o.breached : null}
            tone="critical"
          />
          <KennaStatChip
            icon={<Timer size={16} />}
            label="Mean time to remediate (days)"
            value={o?.mttrDays ?? null}
          />
          <KennaStatChip
            icon={<CheckCircle2 size={16} />}
            label="Resolved (30d)"
            value={o ? o.resolved30 : null}
            tone="ok"
          />
        </div>
      </div>

      <div className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm font-semibold text-white">30-day backlog burndown</div>
          <div className="flex items-center gap-4 text-xs text-zinc-500">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-sm" style={{ background: "#ff4d57" }} /> Open backlog
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-sm" style={{ background: "rgba(16,185,129,0.5)" }} /> Resolved / day
            </span>
          </div>
        </div>
        {data ? <div className="mt-3"><Burndown data={data.burndown} /></div> : null}
        <div className="mt-3 flex flex-wrap gap-2">
          {(data?.slaPolicy ?? []).map((p) => (
            <span key={p.severity} className="rounded-full border border-zinc-800 bg-zinc-950 px-2.5 py-0.5 text-[11px] text-zinc-400">
              {p.severity} SLA: {p.days}d
            </span>
          ))}
        </div>
      </div>

      <div className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="text-sm font-semibold text-white">Per-client SLA health</div>
          <div className="text-xs text-zinc-500">Click a client to drill in</div>
        </div>
        <div className="overflow-x-auto">
          <div className="min-w-[720px]">
            <div className="grid grid-cols-[1.4fr_120px_1fr_90px_90px_90px] gap-3 border-b border-zinc-900 pb-2 text-xs uppercase tracking-[0.16em] text-zinc-500">
              <div>Client</div>
              <div>SLA compliance</div>
              <div>Open (within · due · breached)</div>
              <div className="text-right">Breached</div>
              <div className="text-right">MTTR</div>
              <div className="text-right">Resolved 30d</div>
            </div>
            {(data?.clients ?? []).map((c) => (
              <button
                key={c.companyId}
                type="button"
                aria-pressed={c.companyId === companyId}
                onClick={() => setCompanyId((current) => (current === c.companyId ? "" : c.companyId))}
                className={`relative grid w-full grid-cols-[1.4fr_120px_1fr_90px_90px_90px] items-center gap-3 border-b border-zinc-900/60 py-3 pl-3 text-left text-sm transition-colors hover:bg-zinc-900/40 ${c.companyId === companyId ? "bg-[rgba(179,14,20,0.08)]" : ""}`}
              >
                <div
                  className="absolute inset-y-0 left-0 w-[3px]"
                  style={{ background: complianceColor(c.slaCompliance) }}
                />
                <div className="min-w-0 truncate font-medium text-white">{c.companyName}</div>
                <div>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-900">
                      <div className="h-full rounded-full" style={{ width: `${c.slaCompliance}%`, background: complianceColor(c.slaCompliance) }} />
                    </div>
                    <span className="w-8 text-right text-xs" style={{ color: complianceColor(c.slaCompliance) }}>{c.slaCompliance}%</span>
                  </div>
                </div>
                <div className="text-xs text-zinc-400">
                  <span className="text-emerald-300">{c.withinSla}</span> ·{" "}
                  <span className="text-amber-300">{c.dueSoon}</span> ·{" "}
                  <span className="text-[#ff4d57]">{c.breached}</span>
                  <span className="ml-2 text-zinc-600">of {c.open}</span>
                </div>
                <div className={`text-right font-semibold ${c.breached ? "text-[#ff4d57]" : "text-zinc-500"}`}>{c.breached || "—"}</div>
                <div className="text-right text-zinc-300">{c.mttrDays === null ? "—" : `${c.mttrDays}d`}</div>
                <div className="text-right text-zinc-300">{c.resolved30 || "—"}</div>
              </button>
            ))}
            {data && data.clients.length === 0 ? (
              <div className="py-6 text-center text-sm text-zinc-500">No findings yet.</div>
            ) : null}
          </div>
        </div>
      </div>

      {selected && (
        <section aria-label="Client remediation detail" className="rounded-2xl border border-[rgba(179,14,20,0.22)] bg-[#080808] p-5 sm:p-7">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-[0.25em] text-red-500">Remediation</p>
              <h2 className="mt-2 text-xl font-semibold text-white">{selected.companyName}</h2>
              <p className="mt-2 max-w-2xl text-sm text-zinc-400">
                {selected.breached} breached · {selected.dueSoon} due soon · {selected.withinSla} within SLA.
              </p>
            </div>
            <button type="button" className={ghostButtonClass} onClick={() => setCompanyId("")}>Close</button>
          </div>
          <p className="mt-5 text-sm text-zinc-500">The ConnectWise ticket review queue for this client will move here.</p>
        </section>
      )}
    </VulnShell>
  );
}
