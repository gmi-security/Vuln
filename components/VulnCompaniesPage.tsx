"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Building2, Database, DownloadCloud, FolderKanban, Laptop, Plus, Radar, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { IconAlertTriangle, IconBug } from "@tabler/icons-react";
import VulnShell from "@/components/VulnShell";
import {
  PanelCard,
  Pill,
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
} from "@/components/ui";
import { compositeBandClass, compositeColor } from "@/lib/format";
import type { Company } from "@/lib/types";

export default function VulnCompaniesPage() {
  const [companies, setCompanies] = useState<Company[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importMsg, setImportMsg] = useState<
    { ok: boolean; text: string } | null
  >(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/companies", { cache: "no-store" });
      const json = await res.json();
      setCompanies(json.companies ?? []);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [load]);

  async function importNessus() {
    setImporting(true);
    setImportMsg(null);
    try {
      const res = await fetch("/api/nessus/import", { method: "POST" });
      const json = await res.json();
      if (!res.ok) {
        setImportMsg({ ok: false, text: json.error ?? "Import failed." });
        return;
      }
      const r = json.result;
      setImportMsg({
        ok: true,
        text: `Imported ${r.companiesCreated} new compan${r.companiesCreated === 1 ? "y" : "ies"} (${r.companiesMatched} matched), ${r.scansImported} scans, ${r.findingsImported} findings.`,
      });
      await load();
    } catch {
      setImportMsg({ ok: false, text: "Failed to reach the import API." });
    } finally {
      setImporting(false);
    }
  }

  async function syncIntune() {
    setImporting(true);
    setImportMsg(null);
    try {
      const res = await fetch("/api/intune/import", { method: "POST" });
      const json = await res.json();
      if (!res.ok) {
        setImportMsg({ ok: false, text: json.error ?? "Intune sync failed." });
        return;
      }
      const r = json.result;
      const auto = r.autoScan?.assetsQueued
        ? ` Auto-scan launched ${r.autoScan.scansLaunched} scan${r.autoScan.scansLaunched === 1 ? "" : "s"} for ${r.autoScan.assetsQueued} new asset${r.autoScan.assetsQueued === 1 ? "" : "s"}.`
        : "";
      setImportMsg({
        ok: true,
        text: `Synced ${r.assetsUpserted} Intune device${r.assetsUpserted === 1 ? "" : "s"} to ${r.company}; repriced ${r.findingsRescored} findings.${auto}`,
      });
      await load();
    } catch {
      setImportMsg({ ok: false, text: "Failed to reach the Intune API." });
    } finally {
      setImporting(false);
    }
  }

  async function importDefender() {
    setImporting(true);
    setImportMsg(null);
    try {
      const res = await fetch("/api/defender/import", { method: "POST" });
      const json = await res.json();
      if (!res.ok) {
        setImportMsg({ ok: false, text: json.error ?? "Defender import failed." });
        return;
      }
      const r = json.result;
      setImportMsg({
        ok: true,
        text: `Imported ${r.findingsImported} Defender findings across ${r.hostsAffected} host${r.hostsAffected === 1 ? "" : "s"} to ${r.company}.`,
      });
      await load();
    } catch {
      setImportMsg({ ok: false, text: "Failed to reach the Defender API." });
    } finally {
      setImporting(false);
    }
  }

  async function syncCrowdstrike() {
    setImporting(true);
    setImportMsg(null);
    try {
      const res = await fetch("/api/crowdstrike/import", { method: "POST" });
      const json = await res.json();
      if (!res.ok) {
        setImportMsg({ ok: false, text: json.error ?? "CrowdStrike sync failed." });
        return;
      }
      const r = json.result;
      setImportMsg({
        ok: true,
        text: `Synced ${r.assetsUpserted} CrowdStrike host${r.assetsUpserted === 1 ? "" : "s"} to ${r.company}; repriced ${r.findingsRescored} findings.`,
      });
      await load();
    } catch {
      setImportMsg({ ok: false, text: "Failed to reach the CrowdStrike API." });
    } finally {
      setImporting(false);
    }
  }

  async function syncTidal() {
    setImporting(true);
    setImportMsg(null);
    try {
      const res = await fetch("/api/tidal/import", { method: "POST" });
      const json = await res.json().catch(() => ({}));
      if (!res.ok || json.error) {
        setImportMsg({ ok: false, text: json.error ?? "Tidal sync failed." });
        setImporting(false);
        return;
      }
      // Background job — poll until it finishes (spans ~49 client companies).
      for (let i = 0; i < 3000; i += 1) {
        await new Promise((r) => setTimeout(r, 1200));
        let st: any = null;
        try {
          const pr = await fetch("/api/tidal/import", { cache: "no-store" });
          st = (await pr.json().catch(() => ({}))).status;
        } catch {
          continue;
        }
        if (!st) break;
        if (st.running) {
          setImportMsg({
            ok: true,
            text: `Syncing Tidal… ${st.companiesDone}/${st.companiesTotal || "?"} customers, ${st.assetsFound} assets${st.currentCompany ? ` (${st.currentCompany})` : ""}`,
          });
          continue;
        }
        if (st.error) {
          setImportMsg({ ok: false, text: st.error });
        } else if (st.result) {
          const r = st.result;
          const auto = r.autoScan?.assetsQueued
            ? ` Auto-scan launched ${r.autoScan.scansLaunched} scan${r.autoScan.scansLaunched === 1 ? "" : "s"} for ${r.autoScan.assetsQueued} new asset${r.autoScan.assetsQueued === 1 ? "" : "s"}.`
            : "";
          setImportMsg({
            ok: true,
            text: `Synced ${r.assetsUpserted} assets from Tidal (${r.companiesCreated} new customer${r.companiesCreated === 1 ? "" : "s"}); repriced ${r.findingsRescored} findings.${auto}`,
          });
          await load();
        }
        break;
      }
    } catch {
      setImportMsg({ ok: false, text: "Failed to reach the Tidal API." });
    } finally {
      setImporting(false);
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/companies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, industry, contactName, contactEmail }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error ?? "Failed to add company.");
        return;
      }
      setShowNew(false);
      setName("");
      setIndustry("");
      setContactName("");
      setContactEmail("");
      await load();
    } catch {
      setError("Failed to reach the API.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <VulnShell
      eyebrow="Companies"
      title="Companies"
      subtitle="GMI (our own organization) plus the external clients we scan. Each company groups its scans into folders and rolls up its own open findings and exposure."
      actions={
        <>
          <button
            onClick={() => void syncTidal()}
            disabled={importing}
            className={`${ghostButtonClass} disabled:opacity-50`}
          >
            <Database size={16} className="text-zinc-400" />
            Sync from Tidal
          </button>
          <button
            onClick={() => void syncIntune()}
            disabled={importing}
            className={`${ghostButtonClass} disabled:opacity-50`}
          >
            <Laptop size={16} className="text-zinc-400" />
            Sync from Intune
          </button>
          <button
            onClick={() => void syncCrowdstrike()}
            disabled={importing}
            className={`${ghostButtonClass} disabled:opacity-50`}
          >
            <ShieldCheck size={16} className="text-zinc-400" />
            Sync CrowdStrike hosts
          </button>
          <button
            onClick={() => void importNessus()}
            disabled={importing}
            className={`${ghostButtonClass} disabled:opacity-50`}
          >
            <DownloadCloud size={16} className="text-zinc-400" />
            {importing ? "Importing..." : "Import from Nessus"}
          </button>
          <button
            onClick={() => void importDefender()}
            disabled={importing}
            className={`${ghostButtonClass} disabled:opacity-50`}
          >
            <ShieldAlert size={16} className="text-zinc-400" />
            Import from Defender
          </button>
          <button onClick={() => setShowNew(true)} className={primaryButtonClass}>
            <Plus size={16} />
            Add company
          </button>
        </>
      }
    >
      {importMsg ? (
        <div
          className={[
            "rounded-2xl border px-5 py-4 text-sm",
            importMsg.ok
              ? "border-emerald-900/60 bg-emerald-950/40 text-emerald-300"
              : "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] text-[#ff4d57]",
          ].join(" ")}
        >
          {importMsg.text}
        </div>
      ) : null}

      {companies.length === 0 ? (
        <PanelCard eyebrow="Companies">
          <div className="px-5 py-12 text-center text-sm text-zinc-500">
            No companies yet — add one, or import your Nessus folders.
          </div>
        </PanelCard>
      ) : (
        <div className="grid gap-5 xl:grid-cols-2">
          {companies.map((company) => (
            <Link key={company.id} href={`/companies/${company.id}`}>
              <section className="h-full rounded-[30px] border border-[rgba(179,14,20,0.16)] bg-[#050505] p-5 shadow-[0_20px_80px_rgba(0,0,0,0.34)] transition hover:border-[rgba(179,14,20,0.35)] hover:bg-[#070707]">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className="flex h-14 w-14 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
                      <Building2 size={26} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-xl font-semibold text-white">
                          {company.name}
                        </h2>
                        {company.kind === "internal" ? (
                          <span className="rounded-full border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.14)] px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#ff4d57]">
                            Our org
                          </span>
                        ) : null}
                        {company.isDemo ? (
                          <span
                            title="Demo/test data — excluded from reporting and GRC"
                            className="rounded-full border border-sky-900/60 bg-[rgba(59,130,246,0.12)] px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-sky-300"
                          >
                            Demo
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-1 text-sm text-zinc-500">
                        {company.industry || "—"}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div
                      className="text-3xl font-semibold tracking-[-0.03em]"
                      style={{ color: compositeColor(company.compositeScore) }}
                    >
                      {company.compositeScore}
                    </div>
                    <Pill className={compositeBandClass[company.compositeBand]}>
                      {company.compositeBand}
                    </Pill>
                  </div>
                </div>

                <div className="mt-5 grid grid-cols-4 gap-3">
                  <Stat
                    icon={<IconBug size={18} />}
                    value={company.openFindings}
                    label="Vulns"
                  />
                  <Stat
                    icon={<IconAlertTriangle size={18} />}
                    value={company.criticalOpen}
                    label="Critical"
                  />
                  <Stat
                    icon={<Radar size={18} />}
                    value={company.exposureFindings}
                    label="Exposure"
                  />
                  <Stat
                    icon={<FolderKanban size={18} />}
                    value={company.scanCount}
                    label="Scans"
                  />
                </div>

                <div className="mt-4 flex flex-wrap items-center gap-2">
                  {company.activeScans > 0 ? (
                    <div className="inline-flex items-center gap-2 rounded-full border border-[rgba(179,14,20,0.40)] bg-[rgba(179,14,20,0.10)] px-3 py-1 text-xs text-[#ff4d57]">
                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#ff4d57]" />
                      {company.activeScans} active scan
                      {company.activeScans === 1 ? "" : "s"}
                    </div>
                  ) : null}
                  {company.inventoryAssets > 0 ? (
                    <div className="inline-flex items-center gap-2 rounded-full border border-sky-900/60 bg-[rgba(74,163,255,0.10)] px-3 py-1 text-xs text-sky-300">
                      Inventory: {company.inventoryAssets} asset
                      {company.inventoryAssets === 1 ? "" : "s"}
                      {company.inventoryCoverage >= 0
                        ? ` · ${company.inventoryCoverage}% coverage`
                        : ""}
                    </div>
                  ) : (
                    <div className="inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1 text-xs text-zinc-500">
                      Not in Tidal · context inferred
                    </div>
                  )}
                </div>
              </section>
            </Link>
          ))}
        </div>
      )}

      {showNew ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm">
          <div className="w-full max-w-lg rounded-[30px] border border-[rgba(179,14,20,0.25)] bg-[#070707] p-6 shadow-[0_30px_120px_rgba(0,0,0,0.6)]">
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <div className="text-[13px] uppercase tracking-[0.34em] text-[#b30e14]">
                  New company
                </div>
                <h2 className="mt-2 text-2xl font-semibold text-white">
                  Add a client company
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

            <form onSubmit={submit} className="space-y-4">
              <Field label="Company name">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Northwind Retail"
                  className={inputClass}
                />
              </Field>
              <Field label="Industry">
                <input
                  value={industry}
                  onChange={(e) => setIndustry(e.target.value)}
                  placeholder="e.g. Healthcare"
                  className={inputClass}
                />
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Primary contact">
                  <input
                    value={contactName}
                    onChange={(e) => setContactName(e.target.value)}
                    placeholder="Full name"
                    className={inputClass}
                  />
                </Field>
                <Field label="Contact email">
                  <input
                    value={contactEmail}
                    onChange={(e) => setContactEmail(e.target.value)}
                    placeholder="name@company.com"
                    className={inputClass}
                  />
                </Field>
              </div>

              {error ? (
                <div className="rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.10)] px-4 py-3 text-sm text-[#ff4d57]">
                  {error}
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
                  {submitting ? "Adding..." : "Add company"}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </VulnShell>
  );
}

function Stat({
  icon,
  value,
  label,
}: {
  icon: React.ReactNode;
  value: React.ReactNode;
  label: string;
}) {
  return (
    <div className="rounded-2xl border border-zinc-900 bg-[#090909] p-3 text-center">
      <div className="mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-full border border-[rgba(179,14,20,0.20)] bg-[rgba(179,14,20,0.06)] text-[#b30e14]">
        {icon}
      </div>
      <div className="text-xl font-semibold text-white">{value}</div>
      <div className="text-[11px] uppercase tracking-[0.16em] text-zinc-500">
        {label}
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-2 block text-xs uppercase tracking-[0.2em] text-zinc-500">
        {label}
      </label>
      {children}
    </div>
  );
}
