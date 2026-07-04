"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ExternalLink, RefreshCcw, Search, X } from "lucide-react";
import VulnShell from "@/components/VulnShell";
import {
  PanelCard,
  Pill,
  ghostButtonClass,
  inputClass,
  scrollAreaClass,
  selectClass,
} from "@/components/ui";
import {
  connectorLabels,
  findingStatusClass,
  formatAge,
  formatDateTime,
  severityClass,
} from "@/lib/format";
import type { Finding, FindingStatus } from "@/lib/types";

const STATUSES: FindingStatus[] = [
  "Open",
  "In Remediation",
  "Risk Accepted",
  "False Positive",
  "Resolved",
];

export default function VulnFindingsPage() {
  const searchParams = useSearchParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [connectorFilter, setConnectorFilter] = useState("All");
  const [companyFilter, setCompanyFilter] = useState(
    searchParams.get("company") ?? "All",
  );
  const [companies, setCompanies] = useState<{ id: string; name: string }[]>([]);
  const [exploitOnly, setExploitOnly] = useState(false);
  const [focusId, setFocusId] = useState<string | null>(
    searchParams.get("focus"),
  );
  const [assigneeDraft, setAssigneeDraft] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/findings", { cache: "no-store" });
      const json = await res.json();
      setFindings(json.findings ?? []);
    } catch {
      // keep last snapshot
    }
  }, []);

  useEffect(() => {
    void load();
    void fetch("/api/companies", { cache: "no-store" })
      .then((res) => res.json())
      .then((json) =>
        setCompanies(
          (json.companies ?? []).map((c: { id: string; name: string }) => ({
            id: c.id,
            name: c.name,
          })),
        ),
      )
      .catch(() => undefined);
  }, [load]);

  const focus = useMemo(
    () => findings.find((f) => f.id === focusId) ?? null,
    [findings, focusId],
  );

  useEffect(() => {
    setAssigneeDraft(focus?.assignee ?? "");
  }, [focus?.id, focus?.assignee]);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "All" && f.severity !== severityFilter)
        return false;
      if (statusFilter !== "All" && f.status !== statusFilter) return false;
      if (connectorFilter !== "All" && f.connector !== connectorFilter)
        return false;
      if (companyFilter !== "All" && f.companyId !== companyFilter) return false;
      if (exploitOnly && !f.exploitAvailable) return false;
      if (search) {
        const haystack =
          `${f.cve} ${f.title} ${f.asset} ${f.category} ${f.companyName}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [
    findings,
    search,
    severityFilter,
    statusFilter,
    connectorFilter,
    companyFilter,
    exploitOnly,
  ]);

  async function patchFinding(
    id: string,
    patch: { status?: FindingStatus; assignee?: string | null },
  ) {
    const res = await fetch(`/api/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    if (res.ok) {
      const json = await res.json();
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? json.finding : f)),
      );
    }
  }

  return (
    <VulnShell
      eyebrow="Findings"
      title="Finding triage"
      subtitle="Every vulnerability surfaced by scans, deduplicated per asset. Filter, assign, and track findings through remediation."
    >
      <PanelCard eyebrow="Filters">
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.3fr)_180px_150px_180px_170px_150px_130px]">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500"
              size={18}
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVEs, findings, assets, clients..."
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
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className={selectClass}
          >
            {["All", "Critical", "High", "Medium", "Low", "Info"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className={selectClass}
          >
            <option>All</option>
            {STATUSES.map((s) => (
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
          </select>
          <button
            onClick={() => setExploitOnly((prev) => !prev)}
            className={[
              "flex h-[52px] items-center justify-center gap-2 rounded-2xl border px-4 text-sm transition",
              exploitOnly
                ? "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] text-white"
                : "border-zinc-800 bg-[#0b0b0b] text-zinc-300 hover:bg-[#101010]",
            ].join(" ")}
          >
            Exploitable only
          </button>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </div>
      </PanelCard>

      <PanelCard
        eyebrow="Findings"
        description={`${filtered.length} of ${findings.length} findings`}
      >
        <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
          <div className="grid grid-cols-[110px_150px_1.9fr_1fr_90px_100px_110px_150px_90px] gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
            <div>ID</div>
            <div>CVE</div>
            <div>Finding</div>
            <div>Asset</div>
            <div>CVSS</div>
            <div>Severity</div>
            <div>Source</div>
            <div>Status</div>
            <div>Age</div>
          </div>
          <div className={`max-h-[680px] ${scrollAreaClass}`}>
            {filtered.map((finding) => (
              <button
                key={finding.id}
                onClick={() => setFocusId(finding.id)}
                className={[
                  "grid w-full grid-cols-[110px_150px_1.9fr_1fr_90px_100px_110px_150px_90px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 text-left transition last:border-b-0 hover:bg-[#0a0a0a]",
                  focusId === finding.id ? "bg-[rgba(179,14,20,0.06)]" : "",
                ].join(" ")}
              >
                <div className="text-sm font-medium text-[#ff4d57]">
                  {finding.id}
                </div>
                <div className="truncate text-sm text-zinc-300">
                  {finding.cve}
                </div>
                <div className="min-w-0">
                  <div className="truncate font-medium text-white">
                    {finding.title}
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-zinc-500">
                    {finding.category}
                    {finding.exploitAvailable ? (
                      <span className="rounded-full border border-[rgba(179,14,20,0.40)] bg-[rgba(179,14,20,0.10)] px-2 py-0.5 text-[10px] uppercase tracking-[0.14em] text-[#ff4d57]">
                        Exploit
                      </span>
                    ) : null}
                  </div>
                </div>
                <div className="truncate text-sm text-zinc-300">
                  {finding.asset}
                </div>
                <div className="text-sm text-zinc-300">
                  {finding.cvss > 0 ? finding.cvss.toFixed(1) : "—"}
                </div>
                <div>
                  <Pill className={severityClass[finding.severity]}>
                    {finding.severity}
                  </Pill>
                </div>
                <div className="text-sm text-zinc-400">
                  {connectorLabels[finding.connector]}
                </div>
                <div>
                  <Pill className={findingStatusClass[finding.status]}>
                    {finding.status}
                  </Pill>
                </div>
                <div className="text-sm text-zinc-400">
                  {formatAge(finding.firstSeen)}
                </div>
              </button>
            ))}
            {filtered.length === 0 ? (
              <div className="px-5 py-12 text-center text-sm text-zinc-500">
                No findings match the current filters.
              </div>
            ) : null}
          </div>
        </div>
      </PanelCard>

      {focus ? (
        <div className="fixed inset-y-0 right-0 z-40 flex w-full max-w-xl flex-col border-l border-[rgba(179,14,20,0.25)] bg-[#060606] shadow-[-30px_0_120px_rgba(0,0,0,0.6)]">
          <div className="flex items-start justify-between gap-4 border-b border-[rgba(179,14,20,0.12)] px-6 py-5">
            <div className="min-w-0">
              <div className="text-[12px] uppercase tracking-[0.3em] text-[#b30e14]">
                {focus.id} · {focus.cve}
              </div>
              <h2 className="mt-2 text-xl font-semibold text-white">
                {focus.title}
              </h2>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Pill className={severityClass[focus.severity]}>
                  {focus.severity}
                </Pill>
                <Pill className={findingStatusClass[focus.status]}>
                  {focus.status}
                </Pill>
                {focus.exploitAvailable ? (
                  <Pill className="border border-[rgba(179,14,20,0.40)] bg-[rgba(179,14,20,0.10)] text-[#ff4d57]">
                    Exploit available
                  </Pill>
                ) : null}
              </div>
            </div>
            <button
              onClick={() => setFocusId(null)}
              className="rounded-xl border border-zinc-800 bg-[#0b0b0b] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white"
              aria-label="Close"
            >
              <X size={16} />
            </button>
          </div>

          <div className={`flex-1 space-y-6 px-6 py-6 ${scrollAreaClass}`}>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm">
              <Detail label="Company" value={focus.companyName} />
              <Detail label="Asset" value={focus.asset} />
              <Detail label="Port" value={focus.port} />
              <Detail
                label="CVSS"
                value={focus.cvss > 0 ? focus.cvss.toFixed(1) : "—"}
              />
              <Detail
                label="EPSS"
                value={`${Math.round(focus.epss * 100)}%`}
              />
              <Detail
                label="Source"
                value={connectorLabels[focus.connector]}
              />
              <Detail label="Category" value={focus.category} />
              <Detail
                label="First seen"
                value={formatDateTime(focus.firstSeen)}
              />
              <Detail
                label="Last seen"
                value={formatDateTime(focus.lastSeen)}
              />
            </dl>

            <div>
              <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                Description
              </div>
              <p className="mt-2 text-sm leading-relaxed text-zinc-300">
                {focus.description}
              </p>
            </div>

            <div>
              <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                Remediation
              </div>
              <p className="mt-2 text-sm leading-relaxed text-zinc-300">
                {focus.remediation}
              </p>
            </div>

            {focus.cve.startsWith("CVE-") ? (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${focus.cve}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 text-sm text-[#ff4d57] transition hover:text-white"
              >
                <ExternalLink size={14} />
                View {focus.cve} on NVD
              </a>
            ) : null}

            <div className="rounded-2xl border border-zinc-900 bg-[#090909] p-5">
              <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                Triage
              </div>
              <div className="mt-4 space-y-4">
                <div>
                  <label className="mb-2 block text-xs text-zinc-500">
                    Status
                  </label>
                  <select
                    value={focus.status}
                    onChange={(e) =>
                      void patchFinding(focus.id, {
                        status: e.target.value as FindingStatus,
                      })
                    }
                    className={`${selectClass} w-full`}
                  >
                    {STATUSES.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-2 block text-xs text-zinc-500">
                    Assignee
                  </label>
                  <div className="flex gap-2">
                    <input
                      value={assigneeDraft}
                      onChange={(e) => setAssigneeDraft(e.target.value)}
                      placeholder="analyst@gmi.com"
                      className={inputClass}
                    />
                    <button
                      onClick={() =>
                        void patchFinding(focus.id, {
                          assignee: assigneeDraft.trim() || null,
                        })
                      }
                      className="h-[52px] shrink-0 rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] px-5 text-sm text-white transition hover:bg-[rgba(179,14,20,0.28)]"
                    >
                      Assign
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </VulnShell>
  );
}

function Detail({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-zinc-500">{label}</dt>
      <dd className="mt-1 truncate text-zinc-200">{value}</dd>
    </div>
  );
}
