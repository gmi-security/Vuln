"use client";

import React, { useCallback, useEffect, useState } from "react";
import { FileText, RefreshCcw, Upload } from "lucide-react";
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
  const [frameworks, setFrameworks] = useState<
    { id: string; name: string; short: string }[]
  >([]);
  const [selected, setSelected] = useState("pci");
  const [pushing, setPushing] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async (framework: string) => {
    try {
      const res = await fetch(`/api/compliance?framework=${framework}`, {
        cache: "no-store",
      });
      const json = await res.json();
      setData(json.compliance ?? null);
      if (json.frameworks) setFrameworks(json.frameworks);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load(selected);
  }, [load, selected]);

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
      const breakdown =
        r.created != null && r.updated != null
          ? ` (${r.created} created, ${r.updated} updated)`
          : "";
      setMsg({
        ok: r.errors.length === 0,
        text: `Pushed ${r.pushed}/${r.companies} risk record(s) to GRC${breakdown}.${r.errors.length ? ` Errors: ${r.errors.join("; ")}` : ""}`,
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
      title={data?.framework ?? "Compliance"}
      subtitle="Vulnerability-management compliance per client, mapped to controls across PCI DSS, NIST, CMMC, HIPAA & FedRAMP — findings → controls, pass/fail with evidence, pushable to your GRC."
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
          <button onClick={() => void load(selected)} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </>
      }
    >
      {frameworks.length ? (
        <div className="flex flex-wrap gap-2">
          {frameworks.map((fw) => (
            <button
              key={fw.id}
              onClick={() => setSelected(fw.id)}
              title={fw.name}
              className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition ${
                selected === fw.id
                  ? "border-[rgba(179,14,20,0.5)] bg-[rgba(179,14,20,0.14)] text-[#ff8f96]"
                  : "border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-white"
              }`}
            >
              {fw.short}
            </button>
          ))}
        </div>
      ) : null}
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
          sublabel="Non-compliant clients"
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
          <a
            href={`/report/${posture.companyId}`}
            target="_blank"
            rel="noreferrer"
            className={`${ghostButtonClass} h-9 px-3 text-xs`}
          >
            <FileText size={14} className="text-zinc-400" />
            Board PDF
          </a>
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
        <div className="grid grid-cols-[160px_1.5fr_110px_70px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
          <div>Control</div>
          <div>Objective</div>
          <div>Status</div>
          <div>Failing</div>
        </div>
        {posture.requirements.map((r) => (
          <div
            key={r.id}
            className="grid grid-cols-[160px_1.5fr_110px_70px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 last:border-b-0"
          >
            <div className="break-words text-xs font-medium text-[#ff8f96]">{r.id}</div>
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
