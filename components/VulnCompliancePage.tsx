"use client";

import React, { useCallback, useEffect, useState } from "react";
import { RefreshCcw, Upload } from "lucide-react";
import {
  IconBuildingBank,
  IconCircleCheck,
  IconCircleX,
  IconShieldLock,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill, StatCard, ghostButtonClass, primaryButtonClass } from "@/components/ui";
import { compositeColor } from "@/lib/format";
import type { ComplianceResult, CompliancePosture } from "@/lib/types";

const statusClass: Record<string, string> = {
  Pass: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
  Fail: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
  "At Risk": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Info: "bg-zinc-900 text-zinc-400 border border-zinc-800",
};

export default function VulnCompliancePage() {
  const [data, setData] = useState<ComplianceResult | null>(null);
  const [pushing, setPushing] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/compliance", { cache: "no-store" });
      setData((await res.json()).compliance ?? null);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function pushToGrc(companyId?: string) {
    setPushing(true);
    setMsg(null);
    try {
      const res = await fetch("/api/grc/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(companyId ? { companyId } : {}),
      });
      const json = await res.json();
      if (!res.ok) {
        setMsg({ ok: false, text: json.error ?? "GRC export failed." });
        return;
      }
      const r = json.result;
      setMsg({
        ok: r.errors.length === 0,
        text: `Pushed ${r.pushed}/${r.companies} risk record(s) to GRC.${r.errors.length ? ` Errors: ${r.errors.join("; ")}` : ""}`,
      });
    } catch {
      setMsg({ ok: false, text: "Failed to reach the GRC API." });
    } finally {
      setPushing(false);
    }
  }

  const agg = data?.aggregate;

  return (
    <VulnShell
      eyebrow="Compliance"
      title="PCI DSS 4.0"
      subtitle="Vulnerability-management compliance per client — ASV pass/fail, patch-SLA, and internal-scan requirements — pushable to your GRC for audit evidence."
      actions={
        <>
          <button
            onClick={() => void pushToGrc()}
            disabled={pushing}
            className={`${primaryButtonClass} disabled:opacity-50`}
          >
            <Upload size={16} />
            {pushing ? "Pushing..." : "Push all to GRC"}
          </button>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </>
      }
    >
      {msg ? (
        <div
          className={[
            "rounded-2xl border px-5 py-4 text-sm",
            msg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] text-[#ff4d57]",
          ].join(" ")}
        >
          {msg.text}
        </div>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Avg compliance"
          value={agg ? agg.avgScore : "—"}
          sublabel="Across all clients, 0–100"
          icon={<IconShieldLock size={26} />}
        />
        <StatCard
          label="Passing"
          value={agg ? agg.passing : "—"}
          sublabel={`of ${agg?.companies ?? 0} clients`}
          icon={<IconCircleCheck size={26} />}
        />
        <StatCard
          label="Failing"
          value={agg ? agg.failing : "—"}
          sublabel="PCI DSS non-compliant"
          icon={<IconCircleX size={26} />}
        />
        <StatCard
          label="ASV failing"
          value={agg ? agg.asvFailingCompanies : "—"}
          sublabel="CVSS ≥ 4.0 on internet-facing"
          icon={<IconBuildingBank size={26} />}
        />
      </div>

      {(data?.companies ?? []).map((posture) => (
        <ComplianceCard
          key={posture.companyId}
          posture={posture}
          onPush={() => void pushToGrc(posture.companyId)}
          pushing={pushing}
        />
      ))}
    </VulnShell>
  );
}

function ComplianceCard({
  posture,
  onPush,
  pushing,
}: {
  posture: CompliancePosture;
  onPush: () => void;
  pushing: boolean;
}) {
  return (
    <PanelCard
      eyebrow={posture.framework}
      actions={
        <div className="flex items-center gap-4">
          <div
            className="text-3xl font-semibold"
            style={{ color: compositeColor(100 - posture.score) }}
          >
            {posture.score}
          </div>
          <Pill className={statusClass[posture.overall]}>{posture.overall}</Pill>
          <button
            onClick={onPush}
            disabled={pushing}
            className={`${ghostButtonClass} h-9 px-3 text-xs disabled:opacity-50`}
          >
            <Upload size={14} className="text-zinc-400" />
            GRC
          </button>
        </div>
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <span className="text-lg font-semibold text-white">
          {posture.companyName}
        </span>
        <span className="text-zinc-500">
          {posture.summary.openTotal} open · {posture.summary.internalHighCrit}{" "}
          high/critical · {posture.summary.slaBreaches} past SLA ·{" "}
          {posture.lastScanDaysAgo === null
            ? "never scanned"
            : `last scan ${posture.lastScanDaysAgo}d ago`}
        </span>
      </div>

      <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
        <div className="grid grid-cols-[90px_1.8fr_120px_90px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
          <div>Req</div>
          <div>Requirement</div>
          <div>Status</div>
          <div>Failing</div>
        </div>
        {posture.requirements.map((r) => (
          <div
            key={r.id}
            className="grid grid-cols-[90px_1.8fr_120px_90px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 last:border-b-0"
          >
            <div className="font-medium text-[#ff8f96]">{r.id}</div>
            <div className="min-w-0">
              <div className="font-medium text-white">{r.title}</div>
              <div className="mt-1 text-xs text-zinc-500">{r.detail}</div>
            </div>
            <div>
              <Pill className={statusClass[r.status]}>{r.status}</Pill>
            </div>
            <div className="text-sm text-zinc-300">{r.failing || "—"}</div>
          </div>
        ))}
      </div>
    </PanelCard>
  );
}
