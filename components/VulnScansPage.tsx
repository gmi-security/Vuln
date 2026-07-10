"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Building2,
  Folder as FolderIcon,
  Pause,
  Play,
  Plus,
  RefreshCcw,
  Search,
  Square,
  Trash2,
} from "lucide-react";
import VulnShell from "@/components/VulnShell";
import NewScanModal from "@/components/NewScanModal";
import {
  PanelCard,
  Pill,
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
  selectClass,
} from "@/components/ui";
import {
  connectorLabels,
  formatDateTime,
  scanStatusClass,
} from "@/lib/format";
import type { Company, Connector, Scan, ScanProfile } from "@/lib/types";

export default function VulnScansPage({
  profiles,
}: {
  profiles: ScanProfile[];
}) {
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [companies, setCompanies] = useState<Company[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [connectorFilter, setConnectorFilter] = useState("All");
  const [companyFilter, setCompanyFilter] = useState("All");
  const [showNew, setShowNew] = useState(searchParams.get("new") === "1");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/scans", { cache: "no-store" });
      const json = await res.json();
      setScans(json.scans ?? []);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
    void fetch("/api/connectors", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setConnectors(json.connectors ?? []))
      .catch(() => undefined);
    void fetch("/api/companies", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => setCompanies(json.companies ?? []))
      .catch(() => undefined);
    const timer = setInterval(() => void load(), 3000);
    return () => clearInterval(timer);
  }, [load]);

  const filtered = useMemo(() => {
    return scans.filter((scan) => {
      if (statusFilter !== "All" && scan.status !== statusFilter) return false;
      if (connectorFilter !== "All" && scan.connector !== connectorFilter)
        return false;
      if (companyFilter !== "All" && scan.companyId !== companyFilter)
        return false;
      if (search) {
        const haystack =
          `${scan.name} ${scan.id} ${scan.targets.join(" ")} ${scan.companyName} ${scan.folderName}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [scans, search, statusFilter, connectorFilter, companyFilter]);

  // Group filtered scans as company -> folder -> scans[].
  const grouped = useMemo(() => {
    const byCompany = new Map<
      string,
      { name: string; folders: Map<string, { name: string; scans: Scan[] }> }
    >();
    for (const scan of filtered) {
      const company =
        byCompany.get(scan.companyId) ??
        { name: scan.companyName, folders: new Map() };
      const folder =
        company.folders.get(scan.folderId) ??
        { name: scan.folderName, scans: [] };
      folder.scans.push(scan);
      company.folders.set(scan.folderId, folder);
      byCompany.set(scan.companyId, company);
    }
    return Array.from(byCompany.entries())
      .map(([companyId, c]) => ({
        companyId,
        name: c.name,
        folders: Array.from(c.folders.entries())
          .map(([folderId, f]) => ({ folderId, name: f.name, scans: f.scans }))
          .sort((a, b) => a.name.localeCompare(b.name)),
        total: Array.from(c.folders.values()).reduce(
          (sum, f) => sum + f.scans.length,
          0,
        ),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [filtered]);

  async function runAction(scan: Scan, action: string) {
    if (
      action === "delete" &&
      !window.confirm(`Delete ${scan.name} and its findings?`)
    ) {
      return;
    }
    setBusyId(scan.id);
    setActionError(null);
    try {
      const res = await fetch(`/api/scans/${scan.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        setActionError(
          json.error ?? `Failed to ${action} ${scan.name} (HTTP ${res.status}).`,
        );
        return;
      }
      await load();
    } catch {
      setActionError(`Failed to reach the API — could not ${action} ${scan.name}.`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <VulnShell
      eyebrow="Scans"
      title="Scan management"
      subtitle="Scans are organized by client company and folder. Launch, monitor, pause, and re-run across Nessus, Vulners, and CrowdStrike Spotlight."
      actions={
        <button onClick={() => setShowNew(true)} className={primaryButtonClass}>
          <Plus size={16} />
          Start scan
        </button>
      }
    >
      <PanelCard eyebrow="Filters">
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.3fr)_190px_170px_180px_140px]">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500"
              size={18}
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search scans, companies, folders, targets..."
              className={`${inputClass} pl-11`}
            />
          </div>
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
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className={selectClass}
          >
            {[
              "All",
              "Queued",
              "Running",
              "Paused",
              "Completed",
              "Stopped",
              "Failed",
            ].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            value={connectorFilter}
            onChange={(e) => setConnectorFilter(e.target.value)}
            className={selectClass}
          >
            <option value="All">All connectors</option>
            <option value="nessus">Nessus</option>
            <option value="vulners">Vulners</option>
            <option value="crowdstrike">CrowdStrike</option>
            <option value="qualys">Qualys</option>
          </select>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </div>
      </PanelCard>

      {actionError ? (
        <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-5 py-3 text-sm text-[#ff4d57]">
          {actionError}
        </div>
      ) : null}

      {grouped.length === 0 ? (
        <PanelCard eyebrow="All scans">
          <div className="px-5 py-12 text-center text-sm text-zinc-500">
            No scans match the current filters.
          </div>
        </PanelCard>
      ) : null}

      {grouped.map((company) => (
        <PanelCard
          key={company.companyId}
          eyebrow="Client"
          actions={
            <Link
              href={`/companies/${company.companyId}`}
              className="text-sm text-[#ff4d57] transition hover:text-white"
            >
              Open company →
            </Link>
          }
        >
          <div className="mb-4 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
              <Building2 size={20} />
            </div>
            <div>
              <div className="text-lg font-semibold text-white">
                {company.name}
              </div>
              <div className="text-xs text-zinc-500">
                {company.total} scan{company.total === 1 ? "" : "s"} ·{" "}
                {company.folders.length} folder
                {company.folders.length === 1 ? "" : "s"}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {company.folders.map((folder) => (
              <div
                key={folder.folderId}
                className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]"
              >
                <div className="flex items-center gap-2 border-b border-zinc-900 px-5 py-3 text-sm text-zinc-300">
                  <FolderIcon size={15} className="text-[#b30e14]" />
                  <span className="font-medium">{folder.name}</span>
                  <span className="text-xs text-zinc-500">
                    · {folder.scans.length}
                  </span>
                </div>
                <div className="grid grid-cols-[110px_1.7fr_130px_140px_1fr_100px_150px_170px] gap-4 border-b border-zinc-900 px-5 py-3 text-xs uppercase tracking-[0.2em] text-zinc-500">
                  <div>ID</div>
                  <div>Scan</div>
                  <div>Connector</div>
                  <div>Status</div>
                  <div>Progress</div>
                  <div>Findings</div>
                  <div>Started</div>
                  <div>Actions</div>
                </div>
                {folder.scans.map((scan) => {
                  const active =
                    scan.status === "Running" || scan.status === "Paused";
                  return (
                    <div
                      key={scan.id}
                      className="grid grid-cols-[110px_1.7fr_130px_140px_1fr_100px_150px_170px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 last:border-b-0"
                    >
                      <div className="font-medium text-[#ff4d57]">{scan.id}</div>
                      <div className="min-w-0">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="font-medium text-white transition hover:text-[#ff4d57]"
                        >
                          {scan.name}
                        </Link>
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
                      <div className="flex items-center gap-2">
                        {scan.status === "Running" ? (
                          <ActionButton
                            title="Pause"
                            disabled={busyId === scan.id}
                            onClick={() => void runAction(scan, "pause")}
                          >
                            <Pause size={15} />
                          </ActionButton>
                        ) : null}
                        {scan.status === "Paused" ? (
                          <ActionButton
                            title="Resume"
                            disabled={busyId === scan.id}
                            onClick={() => void runAction(scan, "resume")}
                          >
                            <Play size={15} />
                          </ActionButton>
                        ) : null}
                        {active ? (
                          <ActionButton
                            title="Stop"
                            disabled={busyId === scan.id}
                            onClick={() => void runAction(scan, "stop")}
                          >
                            <Square size={15} />
                          </ActionButton>
                        ) : (
                          <ActionButton
                            title="Re-run scan"
                            disabled={busyId === scan.id}
                            onClick={() => void runAction(scan, "rescan")}
                          >
                            <RefreshCcw size={15} />
                          </ActionButton>
                        )}
                        <ActionButton
                          title="Delete"
                          disabled={busyId === scan.id}
                          onClick={() => void runAction(scan, "delete")}
                        >
                          <Trash2 size={15} />
                        </ActionButton>
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </PanelCard>
      ))}

      {showNew ? (
        <NewScanModal
          profiles={profiles}
          connectors={connectors}
          onClose={() => setShowNew(false)}
          onLaunched={() => void load()}
        />
      ) : null}
    </VulnShell>
  );
}

function ActionButton({
  title,
  disabled,
  onClick,
  children,
}: {
  title: string;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      disabled={disabled}
      onClick={onClick}
      className="rounded-xl border border-zinc-800 bg-[#0b0b0b] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white disabled:opacity-40"
    >
      {children}
    </button>
  );
}
