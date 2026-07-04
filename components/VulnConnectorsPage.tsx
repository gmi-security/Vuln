"use client";

import React, { useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { IconCloudLock, IconPackage, IconRadar, IconShieldSearch } from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill } from "@/components/ui";
import type { Connector, ConnectorId, ConnectorStatus } from "@/lib/types";

const connectorIcon: Record<ConnectorId, React.ElementType> = {
  nessus: IconRadar,
  vulners: IconPackage,
  crowdstrike: IconShieldSearch,
  qualys: IconCloudLock,
};

const statusClass: Record<ConnectorStatus, string> = {
  Connected: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
  "Demo Mode": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Planned: "bg-zinc-900 text-zinc-400 border border-zinc-800",
  Error: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
};

export default function VulnConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);

  useEffect(() => {
    void fetch("/api/connectors", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setConnectors(json.connectors ?? []))
      .catch(() => undefined);
  }, []);

  return (
    <VulnShell
      eyebrow="Connectors"
      title="Scanner connectors"
      subtitle="Scan engines and telemetry sources feeding the console. A connector runs in demo mode until its credentials are set in the environment."
    >
      <div className="grid gap-5 xl:grid-cols-2">
        {connectors.map((connector) => {
          const Icon = connectorIcon[connector.id];
          return (
            <PanelCard
              key={connector.id}
              eyebrow={connector.vendor}
              actions={
                <Pill className={statusClass[connector.status]}>
                  {connector.status}
                </Pill>
              }
            >
              <div className="flex items-start gap-4">
                <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
                  <Icon size={26} />
                </div>
                <div className="min-w-0">
                  <h2 className="text-xl font-semibold text-white">
                    {connector.name}
                  </h2>
                  <div className="mt-1 text-sm text-zinc-500">
                    {connector.kind}
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-zinc-400">
                    {connector.description}
                  </p>
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-2">
                {connector.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className="rounded-full border border-zinc-800 bg-zinc-950 px-3 py-1 text-xs text-zinc-300"
                  >
                    {cap}
                  </span>
                ))}
              </div>

              <div className="mt-5 rounded-2xl border border-zinc-900 bg-[#090909] p-4">
                <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                  Configuration
                </div>
                <div className="mt-3 space-y-2">
                  {connector.envVars.map((envVar) => (
                    <div
                      key={envVar}
                      className="flex items-center justify-between gap-4"
                    >
                      <code className="text-sm text-zinc-300">{envVar}</code>
                      <span
                        className={
                          connector.configured
                            ? "text-xs text-emerald-300"
                            : "text-xs text-zinc-500"
                        }
                      >
                        {connector.configured ? "set" : "not set"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <a
                href={connector.docsUrl}
                target="_blank"
                rel="noreferrer"
                className="mt-4 inline-flex items-center gap-2 text-sm text-[#ff4d57] transition hover:text-white"
              >
                <ExternalLink size={14} />
                API documentation
              </a>
            </PanelCard>
          );
        })}
      </div>
    </VulnShell>
  );
}
