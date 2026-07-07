"use client";

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCcw, Flame, ShieldAlert, Clock, CalendarClock } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import { Pill, StatCard, ghostButtonClass } from "@/components/ui";

const cardClass =
  "rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5";
import { compositeColor } from "@/lib/format";

type PriorityItem = {
  id: string;
  companyId: string;
  companyName: string;
  cve: string;
  title: string;
  asset: string;
  severity: string;
  realRisk: number;
  decision: "Act" | "Attend" | "Track*" | "Track";
  slaDays: number;
  dueDate: string;
  overdue: boolean;
  daysLeft: number;
  reasons: string[];
  remediation: string;
  kev: boolean;
  ransomware: boolean;
};

type PrioritiesResult = {
  summary: {
    totalOpen: number;
    act: number;
    attend: number;
    overdue: number;
    kevOverdue: number;
    dueThisWeek: number;
  };
  items: PriorityItem[];
};

const decisionClass: Record<string, string> = {
  Act: "bg-[rgba(179,14,20,0.18)] text-[#ff4d57] border border-[rgba(179,14,20,0.5)]",
  Attend: "bg-[rgba(245,110,35,0.12)] text-orange-300 border border-orange-900/60",
  "Track*": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Track: "bg-zinc-900 text-zinc-400 border border-zinc-800",
};

function dueLabel(item: PriorityItem): { text: string; className: string } {
  if (item.overdue)
    return {
      text: `Overdue ${Math.abs(item.daysLeft)}d`,
      className: "text-[#ff4d57] font-semibold",
    };
  if (item.daysLeft <= 7)
    return { text: `Due in ${item.daysLeft}d`, className: "text-amber-300" };
  return { text: `Due in ${item.daysLeft}d`, className: "text-zinc-500" };
}

export default function VulnPrioritiesPage() {
  const [data, setData] = useState<PrioritiesResult | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/priorities", { cache: "no-store" });
      setData((await res.json()).priorities ?? null);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const s = data?.summary;

  return (
    <VulnShell
      eyebrow="Prioritize"
      title="Priority queue"
      subtitle="Every open finding, ranked by CISA SSVC decision (Act ▸ Attend ▸ Track) then remediation deadline and real-risk. Work it top to bottom — the top of the list is always the most urgent thing across all clients."
      actions={
        <button onClick={() => void load()} className={ghostButtonClass}>
          <RefreshCcw size={16} className="text-zinc-400" />
          Refresh
        </button>
      }
    >
      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Act now"
          value={s ? s.act : "—"}
          sublabel="Immediate remediation"
          icon={<Flame size={26} />}
        />
        <StatCard
          label="Overdue"
          value={s ? s.overdue : "—"}
          sublabel="Past remediation SLA"
          icon={<ShieldAlert size={26} />}
        />
        <StatCard
          label="KEV overdue"
          value={s ? s.kevOverdue : "—"}
          sublabel="Actively exploited, past 14d"
          icon={<Clock size={26} />}
        />
        <StatCard
          label="Due this week"
          value={s ? s.dueThisWeek : "—"}
          sublabel="SLA within 7 days"
          icon={<CalendarClock size={26} />}
        />
      </div>

      <div className="space-y-3">
        {(data?.items ?? []).map((item, idx) => {
          const due = dueLabel(item);
          return (
            <div key={item.id} className={cardClass}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex min-w-0 items-start gap-4">
                  <div className="mt-0.5 w-8 shrink-0 text-right text-sm font-semibold text-zinc-600">
                    {idx + 1}
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill className={decisionClass[item.decision]}>{item.decision}</Pill>
                      {item.kev ? (
                        <Pill className="bg-[rgba(179,14,20,0.14)] text-[#ff8f96] border border-[rgba(179,14,20,0.4)]">
                          KEV
                        </Pill>
                      ) : null}
                      {item.ransomware ? (
                        <Pill className="bg-[rgba(217,70,239,0.14)] text-fuchsia-300 border border-fuchsia-800/70">
                          Ransomware
                        </Pill>
                      ) : null}
                      <span className="text-sm font-medium text-zinc-400">
                        {item.companyName}
                      </span>
                    </div>
                    <div className="mt-2 font-medium text-white">
                      {item.cve} — {item.title}
                    </div>
                    <div className="mt-1 text-xs text-zinc-500">on {item.asset}</div>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {item.reasons.map((r) => (
                        <span
                          key={r}
                          className="rounded-full border border-zinc-800 bg-zinc-950 px-2.5 py-0.5 text-[11px] text-zinc-300"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                    <p className="mt-3 max-w-3xl text-xs leading-relaxed text-zinc-400">
                      <span className="text-zinc-500">Fix: </span>
                      {item.remediation}
                    </p>
                  </div>
                </div>

                <div className="flex shrink-0 items-center gap-5 lg:flex-col lg:items-end lg:gap-2">
                  <div className="text-right">
                    <div
                      className="text-2xl font-semibold"
                      style={{ color: compositeColor(item.realRisk) }}
                    >
                      {item.realRisk}
                    </div>
                    <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-600">
                      real-risk
                    </div>
                  </div>
                  <div className={`text-sm ${due.className}`}>{due.text}</div>
                </div>
              </div>
            </div>
          );
        })}
        {data && data.items.length === 0 ? (
          <div className={cardClass}>
            <div className="py-6 text-center text-sm text-zinc-500">
              No open findings — the queue is clear. 🎉
            </div>
          </div>
        ) : null}
      </div>
    </VulnShell>
  );
}
