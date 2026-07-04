"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Bug,
  Folder as FolderIcon,
  FolderPlus,
  Play,
} from "lucide-react";
import { IconAlertTriangle, IconBug, IconGauge, IconRadar } from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import NewScanModal from "@/components/NewScanModal";
import {
  PanelCard,
  Pill,
  StatCard,
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
} from "@/components/ui";
import { connectorLabels, formatDateTime, scanStatusClass } from "@/lib/format";
import type {
  Company,
  Connector,
  Folder,
  InventoryAsset,
  QuantifyMetrics,
  Scan,
  ScanProfile,
} from "@/lib/types";
import { exposureClass } from "@/lib/format";

const assetSourceLabel: Record<string, string> = {
  tidal: "Tidal",
  intune: "Intune",
  crowdstrike: "CrowdStrike",
  manual: "Manual",
  inferred: "Inferred",
};
const assetSourceClass: Record<string, string> = {
  tidal: "bg-[rgba(74,163,255,0.10)] text-sky-300 border border-sky-900/60",
  intune: "bg-[rgba(74,163,255,0.10)] text-sky-300 border border-sky-900/60",
  crowdstrike: "bg-[rgba(179,14,20,0.10)] text-[#ff8f96] border border-[rgba(179,14,20,0.35)]",
  manual: "bg-zinc-900 text-zinc-300 border border-zinc-800",
  inferred: "bg-zinc-900 text-zinc-500 border border-zinc-800",
};

export default function VulnCompanyDetailPage({
  companyId,
  profiles,
}: {
  companyId: string;
  profiles: ScanProfile[];
}) {
  const [company, setCompany] = useState<Company | null>(null);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [assets, setAssets] = useState<InventoryAsset[]>([]);
  const [metrics, setMetrics] = useState<QuantifyMetrics | null>(null);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [addingFolder, setAddingFolder] = useState(false);
  const [folderName, setFolderName] = useState("");
  const [notFound, setNotFound] = useState(false);

  const load = useCallback(async () => {
    try {
      const [companyRes, foldersRes, scansRes, metricsRes, assetsRes] =
        await Promise.all([
          fetch(`/api/companies/${companyId}`, { cache: "no-store" }),
          fetch(`/api/folders?companyId=${companyId}`, { cache: "no-store" }),
          fetch(`/api/scans?companyId=${companyId}`, { cache: "no-store" }),
          fetch(`/api/metrics?companyId=${companyId}`, { cache: "no-store" }),
          fetch(`/api/assets?companyId=${companyId}`, { cache: "no-store" }),
        ]);
      if (companyRes.status === 404) {
        setNotFound(true);
        return;
      }
      setCompany((await companyRes.json()).company ?? null);
      setFolders((await foldersRes.json()).folders ?? []);
      setScans((await scansRes.json()).scans ?? []);
      setMetrics((await metricsRes.json()).metrics ?? null);
      setAssets((await assetsRes.json()).assets ?? []);
    } catch {
      // keep last snapshot
    }
  }, [companyId]);

  useEffect(() => {
    void load();
    void fetch("/api/connectors", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setConnectors(json.connectors ?? []))
      .catch(() => undefined);
    const timer = setInterval(() => void load(), 4000);
    return () => clearInterval(timer);
  }, [load]);

  const byFolder = useMemo(() => {
    const map = new Map<string, Scan[]>();
    for (const folder of folders) map.set(folder.id, []);
    for (const scan of scans) {
      const list = map.get(scan.folderId) ?? [];
      list.push(scan);
      map.set(scan.folderId, list);
    }
    return map;
  }, [folders, scans]);

  async function addFolder(event: React.FormEvent) {
    event.preventDefault();
    if (!folderName.trim()) return;
    await fetch("/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ companyId, name: folderName }),
    });
    setFolderName("");
    setAddingFolder(false);
    await load();
  }

  async function runAction(scan: Scan, action: string) {
    if (
      action === "delete" &&
      !window.confirm(`Delete ${scan.name} and its findings?`)
    ) {
      return;
    }
    await fetch(`/api/scans/${scan.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    await load();
  }

  if (notFound) {
    return (
      <VulnShell
        eyebrow="Company"
        title="Not found"
        subtitle="This company no longer exists."
        actions={
          <Link href="/companies" className={ghostButtonClass}>
            <ArrowLeft size={16} />
            All companies
          </Link>
        }
      >
        <PanelCard eyebrow="Company">
          <p className="text-zinc-400">
            <Link href="/companies" className="text-[#ff4d57]">
              Back to companies
            </Link>
          </p>
        </PanelCard>
      </VulnShell>
    );
  }

  return (
    <VulnShell
      eyebrow="Company"
      title={company?.name ?? companyId}
      subtitle={
        company
          ? `${company.kind === "internal" ? "Our organization · " : ""}${company.industry || "Client"}${company.contactName ? ` · ${company.contactName}` : ""}${company.contactEmail ? ` · ${company.contactEmail}` : ""}`
          : "Loading company..."
      }
      actions={
        <>
          <Link href="/companies" className={ghostButtonClass}>
            <ArrowLeft size={16} />
            All
          </Link>
          <button onClick={() => setShowNew(true)} className={primaryButtonClass}>
            <Play size={16} />
            Start scan
          </button>
        </>
      }
    >
      <div className="grid gap-5 md:grid-cols-2 2xl:grid-cols-4">
        <StatCard
          label="Open findings"
          value={metrics ? metrics.totalOpen : "—"}
          sublabel={`${metrics?.exploitableOpen ?? 0} with known exploit`}
          icon={<IconBug size={26} />}
        />
        <StatCard
          label="Critical open"
          value={metrics ? metrics.severityCounts.Critical : "—"}
          sublabel={`${metrics?.severityCounts.High ?? 0} high open`}
          icon={<IconAlertTriangle size={26} />}
        />
        <StatCard
          label="Exposure score"
          value={metrics ? metrics.exposureScore : "—"}
          sublabel={`Avg CVSS ${metrics?.avgCvss ?? "—"}`}
          icon={<IconGauge size={26} />}
        />
        <StatCard
          label="Scans"
          value={company ? company.scanCount : "—"}
          sublabel={`${company?.activeScans ?? 0} active · ${folders.length} folders`}
          icon={<IconRadar size={26} />}
        />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Link
          href={`/findings?company=${companyId}`}
          className={ghostButtonClass}
        >
          <Bug size={16} className="text-zinc-400" />
          View findings
        </Link>
        {addingFolder ? (
          <form onSubmit={addFolder} className="flex items-center gap-2">
            <input
              value={folderName}
              onChange={(e) => setFolderName(e.target.value)}
              placeholder="Folder name"
              autoFocus
              className={`${inputClass} h-[46px] w-56`}
            />
            <button type="submit" className={`${primaryButtonClass} h-[46px]`}>
              Add
            </button>
            <button
              type="button"
              onClick={() => setAddingFolder(false)}
              className={`${ghostButtonClass} h-[46px]`}
            >
              Cancel
            </button>
          </form>
        ) : (
          <button
            onClick={() => setAddingFolder(true)}
            className={ghostButtonClass}
          >
            <FolderPlus size={16} className="text-zinc-400" />
            Add folder
          </button>
        )}
      </div>

      <PanelCard
        eyebrow="Asset inventory"
        description="Environmental context for real-risk scoring — synced from Tidal.io or entered manually"
        actions={
          <span className="text-sm text-zinc-500">
            {assets.length} asset{assets.length === 1 ? "" : "s"}
            {company && company.inventoryCoverage >= 0
              ? ` · ${company.inventoryCoverage}% of open findings covered`
              : ""}
          </span>
        }
      >
        {company && company.openFindings > 0 && company.inventoryCoverage < 100 ? (
          <div className="mb-4 rounded-2xl border border-zinc-800 bg-[#080808] px-4 py-3 text-xs leading-relaxed text-zinc-500">
            {assets.length === 0
              ? "This customer has no inventory in Tidal — real risk uses asset context inferred from hostnames. "
              : `${company.inventoryCoverage}% of this customer's open findings use authoritative inventory context; the rest are inferred from hostnames. `}
            Not every customer is in Tidal, so coverage is partial by design —
            inferred context is clearly marked on each finding.
          </div>
        ) : null}
        {assets.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-zinc-800 bg-[#080808] px-5 py-8 text-center text-sm text-zinc-500">
            No inventory yet. Sync from Tidal on the Companies page to populate
            asset exposure and criticality.
          </div>
        ) : (
          <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
            <div className="grid grid-cols-[1.6fr_150px_140px_1fr_110px_90px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
              <div>Asset</div>
              <div>Exposure</div>
              <div>Criticality</div>
              <div>Owner / OS</div>
              <div>Source</div>
              <div>Open</div>
            </div>
            {assets.map((asset) => (
              <div
                key={asset.id}
                className="grid grid-cols-[1.6fr_150px_140px_1fr_110px_90px] items-center gap-4 border-b border-zinc-900/70 px-5 py-3 last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="truncate font-medium text-white">
                    {asset.identifier}
                  </div>
                  {asset.ipAddresses.length ? (
                    <div className="mt-1 truncate text-xs text-zinc-500">
                      {asset.ipAddresses.join(", ")}
                    </div>
                  ) : null}
                </div>
                <div
                  className={`text-sm ${exposureClass[asset.exposure] ?? "text-zinc-300"}`}
                >
                  {asset.exposure}
                </div>
                <div className="text-sm text-zinc-300">{asset.criticality}</div>
                <div className="min-w-0 text-sm text-zinc-400">
                  <div className="truncate">{asset.owner || "—"}</div>
                  <div className="truncate text-xs text-zinc-600">
                    {asset.os || ""}
                  </div>
                </div>
                <div>
                  <Pill className={assetSourceClass[asset.source]}>
                    {assetSourceLabel[asset.source]}
                  </Pill>
                </div>
                <div className="text-sm text-zinc-300">{asset.openFindings}</div>
              </div>
            ))}
          </div>
        )}
      </PanelCard>

      {folders.map((folder) => {
        const folderScans = byFolder.get(folder.id) ?? [];
        return (
          <PanelCard
            key={folder.id}
            eyebrow="Folder"
            actions={
              <span className="text-sm text-zinc-500">
                {folderScans.length} scan
                {folderScans.length === 1 ? "" : "s"}
              </span>
            }
          >
            <div className="mb-4 flex items-center gap-2">
              <FolderIcon size={18} className="text-[#b30e14]" />
              <span className="text-lg font-semibold text-white">
                {folder.name}
              </span>
            </div>

            {folderScans.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-zinc-800 bg-[#080808] px-5 py-8 text-center text-sm text-zinc-500">
                No scans in this folder yet.
              </div>
            ) : (
              <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
                <div className="grid grid-cols-[110px_1.8fr_130px_140px_1fr_100px_150px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
                  <div>ID</div>
                  <div>Scan</div>
                  <div>Connector</div>
                  <div>Status</div>
                  <div>Progress</div>
                  <div>Findings</div>
                  <div>Started</div>
                </div>
                {folderScans.map((scan) => (
                  <Link
                    key={scan.id}
                    href={`/scans/${scan.id}`}
                    className="grid grid-cols-[110px_1.8fr_130px_140px_1fr_100px_150px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 transition last:border-b-0 hover:bg-[#0a0a0a]"
                  >
                    <div className="font-medium text-[#ff4d57]">{scan.id}</div>
                    <div className="min-w-0">
                      <div className="truncate font-medium text-white">
                        {scan.name}
                      </div>
                      <div className="mt-1 truncate text-xs text-zinc-500">
                        {scan.targets.join(", ")} · {scan.profile}
                      </div>
                    </div>
                    <div className="text-sm text-zinc-300">
                      {connectorLabels[scan.connector]}
                    </div>
                    <div>
                      <Pill className={scanStatusClass[scan.status]}>
                        {scan.status}
                      </Pill>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-[#101010]">
                        <div
                          className={[
                            "h-full rounded-full transition-all duration-700",
                            scan.status === "Completed"
                              ? "bg-emerald-500/70"
                              : "bg-[linear-gradient(90deg,#b30e14,#ff4d57)]",
                          ].join(" ")}
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                      <span className="w-10 text-right text-xs text-zinc-400">
                        {scan.progress}%
                      </span>
                    </div>
                    <div className="text-sm text-zinc-300">
                      {scan.status === "Completed" || scan.status === "Stopped"
                        ? scan.findingsCount
                        : "—"}
                    </div>
                    <div className="text-sm text-zinc-400">
                      {formatDateTime(scan.startedAt)}
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </PanelCard>
        );
      })}

      {showNew && company ? (
        <NewScanModal
          profiles={profiles}
          connectors={connectors}
          lockedCompany={company}
          onClose={() => setShowNew(false)}
          onLaunched={() => void load()}
        />
      ) : null}
    </VulnShell>
  );
}
