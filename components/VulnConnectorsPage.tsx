"use client";

import React, { useEffect, useState } from "react";
import { ExternalLink, RefreshCw } from "lucide-react";
import {
  IconClipboardCheck,
  IconCloudLock,
  IconDatabaseCog,
  IconDeviceLaptop,
  IconPackage,
  IconRadar,
  IconShieldSearch,
  IconSpider,
  IconTopologyStar3,
} from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import { PanelCard, Pill } from "@/components/ui";
import type { Connector, ConnectorStatus } from "@/lib/types";

type CardData = {
  id: string;
  name: string;
  vendor: string;
  kind: string;
  description: string;
  capabilities: string[];
  envVars: string[];
  configured: boolean;
  status: ConnectorStatus;
  docsUrl: string;
};

const cardIcon: Record<string, React.ElementType> = {
  nessus: IconRadar,
  vulners: IconPackage,
  crowdstrike: IconShieldSearch,
  defender: IconShieldSearch,
  qualys: IconCloudLock,
  spiderfoot: IconSpider,
  artemis: IconTopologyStar3,
  tidal: IconDatabaseCog,
  intune: IconDeviceLaptop,
  "crowdstrike-devices": IconShieldSearch,
  grc: IconClipboardCheck,
};

// Connectors with a pull/import endpoint get a "Sync now" button.
const SYNC_ENDPOINTS: Record<string, string> = {
  nessus: "/api/nessus/import",
  crowdstrike: "/api/crowdstrike/import",
  "crowdstrike-devices": "/api/crowdstrike/import",
  defender: "/api/defender/import",
  spiderfoot: "/api/spiderfoot/import",
  artemis: "/api/artemis/import",
  tidal: "/api/tidal/import",
  intune: "/api/intune/import",
};

// Render a human summary from the various import result shapes.
function summarizeSync(result: any): string {
  if (!result || typeof result !== "object") return "Sync complete.";
  const parts: string[] = [];
  const n = (v: unknown) => (typeof v === "number" ? v : null);
  if (n(result.findingsImported) != null) parts.push(`${result.findingsImported} findings`);
  if (n(result.scansImported) != null) parts.push(`${result.scansImported} scans`);
  if (n(result.assetsUpserted) != null) parts.push(`${result.assetsUpserted} assets`);
  if (n(result.companiesCreated)) parts.push(`${result.companiesCreated} new companies`);
  if (n(result.companiesMatched) != null) parts.push(`${result.companiesMatched} companies`);
  const skipped = Array.isArray(result.skipped) ? result.skipped.length : 0;
  if (skipped) parts.push(`${skipped} skipped`);
  return parts.length ? `Synced — ${parts.join(", ")}.` : "Sync complete.";
}

const statusClass: Record<ConnectorStatus, string> = {
  Connected: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
  "Demo Mode": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Planned: "bg-zinc-900 text-zinc-400 border border-zinc-800",
  Error: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
};

function IntegrationCard({ card }: { card: CardData }) {
  const Icon = cardIcon[card.id] ?? IconRadar;
  const syncUrl = SYNC_ENDPOINTS[card.id];
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function runSync() {
    if (!syncUrl || syncing) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await fetch(syncUrl, { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setSyncMsg({
          ok: false,
          text: json.error ?? `Sync failed (HTTP ${res.status})`,
        });
      } else {
        setSyncMsg({ ok: true, text: summarizeSync(json.result ?? json) });
      }
    } catch (err) {
      setSyncMsg({
        ok: false,
        text: err instanceof Error ? err.message : "Sync failed.",
      });
    } finally {
      setSyncing(false);
    }
  }

  return (
    <PanelCard
      eyebrow={card.vendor}
      actions={<Pill className={statusClass[card.status]}>{card.status}</Pill>}
    >
      <div className="flex items-start gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
          <Icon size={26} />
        </div>
        <div className="min-w-0">
          <h2 className="text-xl font-semibold text-white">{card.name}</h2>
          <div className="mt-1 text-sm text-zinc-500">{card.kind}</div>
          <p className="mt-3 text-sm leading-relaxed text-zinc-400">
            {card.description}
          </p>
        </div>
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {card.capabilities.map((cap) => (
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
          {card.envVars.map((envVar) => (
            <div key={envVar} className="flex items-center justify-between gap-4">
              <code className="text-sm text-zinc-300">{envVar}</code>
              <span
                className={
                  card.configured
                    ? "text-xs text-emerald-300"
                    : "text-xs text-zinc-500"
                }
              >
                {card.configured ? "set" : "not set"}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between gap-3">
        <a
          href={card.docsUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 text-sm text-[#ff4d57] transition hover:text-white"
        >
          <ExternalLink size={14} />
          Documentation
        </a>
        {syncUrl ? (
          <button
            type="button"
            onClick={runSync}
            disabled={syncing || !card.configured}
            title={
              card.configured
                ? "Pull the latest scan results into the console"
                : "Set this connector's environment variables to enable sync"
            }
            className="inline-flex items-center gap-2 rounded-lg border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] px-3 py-1.5 text-sm font-medium text-[#ff4d57] transition hover:bg-[rgba(179,14,20,0.2)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw size={14} className={syncing ? "animate-spin" : ""} />
            {syncing ? "Syncing…" : "Sync now"}
          </button>
        ) : null}
      </div>

      {syncMsg ? (
        <div
          className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
            syncMsg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.12)] text-[#ff8a8a]"
          }`}
        >
          {syncMsg.text}
        </div>
      ) : null}
    </PanelCard>
  );
}

export default function VulnConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [integrations, setIntegrations] = useState<CardData[]>([]);

  useEffect(() => {
    void fetch("/api/connectors", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setConnectors(json.connectors ?? []))
      .catch(() => undefined);
    void fetch("/api/integrations", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setIntegrations(json.integrations ?? []))
      .catch(() => undefined);
  }, []);

  return (
    <VulnShell
      eyebrow="Connectors"
      title="Connectors & integrations"
      subtitle="Scan engines, telemetry sources, and asset inventory feeding the console. Each integration runs in demo mode until its credentials are set in the environment."
    >
      <div className="text-[13px] uppercase tracking-[0.3em] text-[#b30e14]">
        Scanners
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        {connectors.map((connector) => (
          <IntegrationCard key={connector.id} card={connector as CardData} />
        ))}
      </div>

      <div className="mt-2 text-[13px] uppercase tracking-[0.3em] text-[#b30e14]">
        Asset inventory
      </div>
      <div className="grid gap-5 xl:grid-cols-2">
        {integrations.map((integration) => (
          <IntegrationCard key={integration.id} card={integration} />
        ))}
      </div>
    </VulnShell>
  );
}
