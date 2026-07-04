"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Pause,
  Play,
  Plus,
  RefreshCcw,
  Search,
  Square,
  Trash2,
  X,
} from "lucide-react";
import VulnShell from "@/components/VulnShell";
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
import type { Connector, Scan, ScanProfile } from "@/lib/types";

export default function VulnScansPage({
  profiles,
}: {
  profiles: ScanProfile[];
}) {
  const searchParams = useSearchParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [connectorFilter, setConnectorFilter] = useState("All");
  const [showNew, setShowNew] = useState(searchParams.get("new") === "1");
  const [busyId, setBusyId] = useState<string | null>(null);

  // New scan form
  const [name, setName] = useState("");
  const [connector, setConnector] = useState("nessus");
  const [profile, setProfile] = useState("standard");
  const [targets, setTargets] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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
    const timer = setInterval(() => void load(), 3000);
    return () => clearInterval(timer);
  }, [load]);

  const filtered = useMemo(() => {
    return scans.filter((scan) => {
      if (statusFilter !== "All" && scan.status !== statusFilter) return false;
      if (connectorFilter !== "All" && scan.connector !== connectorFilter)
        return false;
      if (search) {
        const haystack =
          `${scan.name} ${scan.id} ${scan.targets.join(" ")}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [scans, search, statusFilter, connectorFilter]);

  async function submitScan(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, connector, profile, targets }),
      });
      const json = await res.json();
      if (!res.ok) {
        setFormError(json.error ?? "Failed to start scan.");
        return;
      }
      setShowNew(false);
      setName("");
      setTargets("");
      await load();
    } catch {
      setFormError("Failed to reach the scan API.");
    } finally {
      setSubmitting(false);
    }
  }

  async function runAction(scan: Scan, action: string) {
    if (
      action === "delete" &&
      !window.confirm(`Delete ${scan.name} and its findings?`)
    ) {
      return;
    }
    setBusyId(scan.id);
    try {
      await fetch(`/api/scans/${scan.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      await load();
    } finally {
      setBusyId(null);
    }
  }

  const selectableConnectors = connectors.filter((c) => c.status !== "Planned");

  return (
    <VulnShell
      eyebrow="Scans"
      title="Scan management"
      subtitle="Launch, monitor, pause, and re-run vulnerability scans across Nessus, Vulners package audits, and CrowdStrike Spotlight telemetry syncs."
      actions={
        <button onClick={() => setShowNew(true)} className={primaryButtonClass}>
          <Plus size={16} />
          Start scan
        </button>
      }
    >
      <PanelCard eyebrow="Filters">
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.4fr)_200px_200px_150px]">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500"
              size={18}
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search scans, targets, ids..."
              className={`${inputClass} pl-11`}
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className={selectClass}
          >
            {["All", "Running", "Paused", "Completed", "Stopped", "Failed"].map(
              (s) => (
                <option key={s}>{s}</option>
              ),
            )}
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

      <PanelCard
        eyebrow="All scans"
        description="Progress updates live while scans run"
      >
        <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
          <div className="grid grid-cols-[110px_1.7fr_130px_150px_1fr_110px_150px_190px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
            <div>ID</div>
            <div>Scan</div>
            <div>Connector</div>
            <div>Status</div>
            <div>Progress</div>
            <div>Findings</div>
            <div>Started</div>
            <div>Actions</div>
          </div>
          {filtered.map((scan) => {
            const active =
              scan.status === "Running" || scan.status === "Paused";
            return (
              <div
                key={scan.id}
                className="grid grid-cols-[110px_1.7fr_130px_150px_1fr_110px_150px_190px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 last:border-b-0"
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
          {filtered.length === 0 ? (
            <div className="px-5 py-12 text-center text-sm text-zinc-500">
              No scans match the current filters.
            </div>
          ) : null}
        </div>
      </PanelCard>

      {showNew ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm">
          <div className="w-full max-w-xl rounded-[30px] border border-[rgba(179,14,20,0.25)] bg-[#070707] p-6 shadow-[0_30px_120px_rgba(0,0,0,0.6)]">
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <div className="text-[13px] uppercase tracking-[0.34em] text-[#b30e14]">
                  New scan
                </div>
                <h2 className="mt-2 text-2xl font-semibold text-white">
                  Start a vulnerability scan
                </h2>
              </div>
              <button
                onClick={() => setShowNew(false)}
                className="rounded-xl border border-zinc-800 bg-[#0b0b0b] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white"
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={submitScan} className="space-y-4">
              <div>
                <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-zinc-500">
                  Scan name
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Weekly External Vulnerability Scan"
                  className={inputClass}
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-zinc-500">
                    Connector
                  </label>
                  <select
                    value={connector}
                    onChange={(e) => setConnector(e.target.value)}
                    className={`${selectClass} w-full`}
                  >
                    {selectableConnectors.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                        {c.status === "Demo Mode" ? " (demo)" : ""}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-zinc-500">
                    Profile
                  </label>
                  <select
                    value={profile}
                    onChange={(e) => setProfile(e.target.value)}
                    className={`${selectClass} w-full`}
                  >
                    {profiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-zinc-500">
                  Targets (hosts, IPs, or CIDR — comma or newline separated)
                </label>
                <textarea
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  placeholder={"10.10.0.0/24\nvpn.gmi.com"}
                  rows={3}
                  className="w-full rounded-2xl border border-zinc-800 bg-[#0b0b0b] px-4 py-3 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-[rgba(179,14,20,0.34)]"
                />
              </div>

              {formError ? (
                <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-4 py-3 text-sm text-[#ff4d57]">
                  {formError}
                </div>
              ) : null}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNew(false)}
                  className={ghostButtonClass}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className={`${primaryButtonClass} disabled:opacity-50`}
                >
                  <Play size={16} />
                  {submitting ? "Launching..." : "Launch scan"}
                </button>
              </div>
            </form>
          </div>
        </div>
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
