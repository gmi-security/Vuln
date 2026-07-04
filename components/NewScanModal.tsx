"use client";

import React, { useEffect, useMemo, useState } from "react";
import { Play, X } from "lucide-react";
import {
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
  selectClass,
} from "@/components/ui";
import type { Company, Connector, Folder, ScanProfile } from "@/lib/types";

// Shared "start a scan" dialog. Optionally pinned to a company (company
// selector hidden) when launched from a company page.
export default function NewScanModal({
  profiles,
  connectors,
  onClose,
  onLaunched,
  lockedCompany,
}: {
  profiles: ScanProfile[];
  connectors: Connector[];
  onClose: () => void;
  onLaunched: () => void;
  lockedCompany?: Company;
}) {
  const [companies, setCompanies] = useState<Company[]>(
    lockedCompany ? [lockedCompany] : [],
  );
  const [folders, setFolders] = useState<Folder[]>([]);
  const [name, setName] = useState("");
  const [companyId, setCompanyId] = useState(lockedCompany?.id ?? "");
  const [folderMode, setFolderMode] = useState<"existing" | "new">("existing");
  const [folderId, setFolderId] = useState("");
  const [newFolder, setNewFolder] = useState("");
  const [connector, setConnector] = useState("nessus");
  const [profile, setProfile] = useState("standard");
  const [targets, setTargets] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (lockedCompany) return;
    void fetch("/api/companies", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => {
        const list: Company[] = json.companies ?? [];
        setCompanies(list);
        if (!companyId && list.length) setCompanyId(list[0].id);
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lockedCompany]);

  useEffect(() => {
    if (!companyId) {
      setFolders([]);
      return;
    }
    void fetch(`/api/folders?companyId=${companyId}`, { cache: "no-store" })
      .then((res) => res.json())
      .then((json) => {
        const list: Folder[] = json.folders ?? [];
        setFolders(list);
        setFolderId((prev) =>
          list.some((f) => f.id === prev) ? prev : list[0]?.id ?? "",
        );
      })
      .catch(() => undefined);
  }, [companyId]);

  const selectableConnectors = useMemo(
    () => connectors.filter((c) => c.status !== "Planned"),
    [connectors],
  );

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          connector,
          profile,
          targets,
          companyId,
          folderId: folderMode === "existing" ? folderId : undefined,
          folderName: folderMode === "new" ? newFolder : undefined,
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error ?? "Failed to start scan.");
        return;
      }
      onLaunched();
      onClose();
    } catch {
      setError("Failed to reach the scan API.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm">
      <div className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-[30px] border border-[rgba(179,14,20,0.25)] bg-[#070707] p-6 shadow-[0_30px_120px_rgba(0,0,0,0.6)]">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <div className="text-[13px] uppercase tracking-[0.34em] text-[#b30e14]">
              New scan
            </div>
            <h2 className="mt-2 text-2xl font-semibold text-white">
              Start a vulnerability scan
            </h2>
            {lockedCompany ? (
              <p className="mt-2 text-sm text-zinc-500">
                For{" "}
                <span className="text-zinc-300">{lockedCompany.name}</span>
              </p>
            ) : null}
          </div>
          <button
            onClick={onClose}
            className="rounded-xl border border-zinc-800 bg-[#0b0b0b] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
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
                Company
              </label>
              {lockedCompany ? (
                <div className="flex h-[52px] items-center rounded-2xl border border-zinc-800 bg-[#0b0b0b] px-4 text-sm text-zinc-300">
                  {lockedCompany.name}
                </div>
              ) : (
                <select
                  value={companyId}
                  onChange={(e) => setCompanyId(e.target.value)}
                  className={`${selectClass} w-full`}
                >
                  {companies.length === 0 ? (
                    <option value="">No companies — add one first</option>
                  ) : null}
                  {companies.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="mb-2 flex items-center justify-between text-xs uppercase tracking-[0.2em] text-zinc-500">
                <span>Folder</span>
                <button
                  type="button"
                  onClick={() =>
                    setFolderMode((m) => (m === "existing" ? "new" : "existing"))
                  }
                  className="text-[10px] text-[#ff4d57] transition hover:text-white"
                >
                  {folderMode === "existing" ? "+ New folder" : "Pick existing"}
                </button>
              </label>
              {folderMode === "existing" ? (
                <select
                  value={folderId}
                  onChange={(e) => setFolderId(e.target.value)}
                  className={`${selectClass} w-full`}
                >
                  {folders.length === 0 ? (
                    <option value="">General</option>
                  ) : null}
                  {folders.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.name}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  value={newFolder}
                  onChange={(e) => setNewFolder(e.target.value)}
                  placeholder="e.g. External, PCI, Servers"
                  className={inputClass}
                />
              )}
            </div>
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

          {error ? (
            <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-4 py-3 text-sm text-[#ff4d57]">
              {error}
            </div>
          ) : null}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className={ghostButtonClass}>
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
  );
}
