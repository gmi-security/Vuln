"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import {
  PanelCard,
  Pill,
  ghostButtonClass,
  inputClass,
  primaryButtonClass,
} from "@/components/ui";
import type { CompensatingControl, CompensatingControlStatus } from "@/lib/types";

const statusClass: Record<CompensatingControlStatus, string> = {
  Active: "bg-[rgba(16,185,129,0.10)] text-emerald-300 border border-emerald-900/60",
  "Under Review": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Expired: "bg-zinc-900 text-zinc-500 border border-zinc-800",
};

const emptyForm = {
  title: "",
  description: "",
  cveMatch: "",
  assetMatch: "",
  effectivenessPct: 50,
  evidence: "",
  reviewBy: "",
};

// A documented mitigation that reduces a finding's real-risk score without
// closing the underlying vulnerability (the PCI DSS "compensating control"
// concept, applied across every framework this console scores). Scoped to
// one customer — self-contained data fetching so it doesn't have to weave
// into VulnCompanyDetailPage's own load()/loadSeq race-guard machinery.
export default function CompensatingControlsPanel({ companyId }: { companyId: string }) {
  const [controls, setControls] = useState<CompensatingControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/compensating-controls?companyId=${companyId}`, {
        cache: "no-store",
      });
      const json = await res.json();
      setControls(json.controls ?? []);
    } catch {
      // keep last snapshot
    } finally {
      setLoading(false);
    }
  }, [companyId]);

  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);

  async function createControl() {
    if (!form.title.trim()) {
      setError("Title is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await fetch("/api/compensating-controls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          companyId,
          title: form.title,
          description: form.description,
          cveMatch: form.cveMatch || null,
          assetMatch: form.assetMatch || null,
          effectivenessPct: Number(form.effectivenessPct),
          evidence: form.evidence,
          reviewBy: form.reviewBy || null,
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error ?? "Could not create control.");
        return;
      }
      setForm(emptyForm);
      setShowNew(false);
      await load();
    } catch {
      setError("Could not create control.");
    } finally {
      setSaving(false);
    }
  }

  async function setStatus(id: string, status: CompensatingControlStatus) {
    await fetch(`/api/compensating-controls/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    await load();
  }

  async function remove(id: string) {
    if (
      !confirm(
        "Delete this compensating control? Affected findings will rescore back to their unadjusted risk.",
      )
    ) {
      return;
    }
    await fetch(`/api/compensating-controls/${id}`, { method: "DELETE" });
    await load();
  }

  return (
    <PanelCard
      eyebrow="Compensating controls"
      description="Documented mitigations that reduce a finding's real-risk score without closing the underlying vulnerability — the PCI DSS concept, applied across every framework this console scores."
      actions={
        <button
          type="button"
          onClick={() => setShowNew((v) => !v)}
          className={ghostButtonClass}
        >
          <Plus size={16} />
          Add control
        </button>
      }
    >
      {showNew ? (
        <div className="mb-5 space-y-3 rounded-2xl border border-zinc-900 bg-[#090909] p-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <input
              className={inputClass}
              placeholder="Title (e.g. WAF blocks exploitation path)"
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
            />
            <input
              className={inputClass}
              placeholder="CVE (optional — blank applies to all)"
              value={form.cveMatch}
              onChange={(e) => setForm({ ...form, cveMatch: e.target.value })}
            />
            <input
              className={inputClass}
              placeholder="Asset match (optional substring)"
              value={form.assetMatch}
              onChange={(e) => setForm({ ...form, assetMatch: e.target.value })}
            />
            <div className="flex items-center gap-3">
              <label className="text-xs text-zinc-500">Effectiveness</label>
              <input
                type="number"
                min={0}
                max={100}
                className={`${inputClass} w-24`}
                value={form.effectivenessPct}
                onChange={(e) => setForm({ ...form, effectivenessPct: Number(e.target.value) })}
              />
              <span className="text-xs text-zinc-500">% risk reduction</span>
            </div>
          </div>
          <textarea
            className={inputClass}
            rows={2}
            placeholder="Description — what the control is and how it mitigates this"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <textarea
            className={inputClass}
            rows={2}
            placeholder="Evidence — what was verified, links, ticket refs"
            value={form.evidence}
            onChange={(e) => setForm({ ...form, evidence: e.target.value })}
          />
          <div className="flex items-center gap-3">
            <label className="text-xs text-zinc-500">Review by</label>
            <input
              type="date"
              className={`${inputClass} w-auto`}
              value={form.reviewBy}
              onChange={(e) => setForm({ ...form, reviewBy: e.target.value })}
            />
          </div>
          {error ? <div className="text-sm text-[#ff8a8a]">{error}</div> : null}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setShowNew(false)} className={ghostButtonClass}>
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void createControl()}
              disabled={saving}
              className={primaryButtonClass}
            >
              {saving ? "Saving…" : "Save control"}
            </button>
          </div>
        </div>
      ) : null}

      {loading ? (
        <div className="text-sm text-zinc-500">Loading…</div>
      ) : controls.length === 0 ? (
        <div className="text-sm text-zinc-500">
          No compensating controls recorded for this customer yet.
        </div>
      ) : (
        <div className="space-y-3">
          {controls.map((c) => (
            <div key={c.id} className="rounded-2xl border border-zinc-900 bg-[#090909] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <ShieldCheck size={16} className="text-emerald-400" />
                    <span className="font-medium text-white">{c.title}</span>
                    <Pill className={statusClass[c.status]}>{c.status}</Pill>
                  </div>
                  <div className="mt-1 text-xs text-zinc-500">
                    {c.cveMatch ? `${c.cveMatch} · ` : "All CVEs · "}
                    {c.assetMatch ? `matches "${c.assetMatch}" · ` : "all assets · "}
                    reduces real risk by {c.effectivenessPct}%
                  </div>
                  {c.description ? (
                    <p className="mt-2 text-sm text-zinc-400">{c.description}</p>
                  ) : null}
                  {c.evidence ? (
                    <p className="mt-2 text-xs text-zinc-500">Evidence: {c.evidence}</p>
                  ) : null}
                  {c.reviewBy ? (
                    <div className="mt-2 text-xs text-zinc-500">Review by {c.reviewBy}</div>
                  ) : null}
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <select
                    value={c.status}
                    onChange={(e) => void setStatus(c.id, e.target.value as CompensatingControlStatus)}
                    className={`${inputClass} w-auto text-xs`}
                  >
                    <option value="Active">Active</option>
                    <option value="Under Review">Under Review</option>
                    <option value="Expired">Expired</option>
                  </select>
                  <button
                    type="button"
                    onClick={() => void remove(c.id)}
                    aria-label="Delete control"
                    className="rounded-lg border border-zinc-800 p-2 text-zinc-500 transition hover:border-[rgba(179,14,20,0.45)] hover:text-[#ff8a8a]"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </PanelCard>
  );
}
