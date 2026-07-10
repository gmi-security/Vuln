"use client";

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useSearchParams } from "next/navigation";
import {
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  RefreshCcw,
  Search,
  X,
} from "lucide-react";
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
  exposureClass,
  findingStatusClass,
  formatAge,
  formatDateTime,
  riskColor,
  riskPriorityClass,
  severityClass,
} from "@/lib/format";
import type { CvssVersion, Finding, FindingStatus } from "@/lib/types";

// Finding plus the aging fields the API now returns per row. Kept as a local
// extension so the page renders cleanly whether or not the fields are present.
type FindingRow = Finding & { dueAt?: string | null; overdue?: boolean };

// Per-company outcome of a bulk remediation request.
type RemediationResult = {
  sent: { companyId: string; count: number }[];
  skipped: { companyId: string; reason: string }[];
};

const SELECTION_CAP = 100;

const STATUSES: FindingStatus[] = [
  "Open",
  "In Remediation",
  "Risk Accepted",
  "False Positive",
  "Resolved",
];

const PAGE_SIZE = 200;

// Score for the selected CVSS version, falling back to the other version when
// the source only carries one. Returns the number and which version was used.
function cvssFor(
  finding: FindingRow,
  version: CvssVersion,
): { value: number; used: CvssVersion | null } {
  const primary = version === "v3" ? finding.cvssV3 : finding.cvssV2;
  if (primary > 0) return { value: primary, used: version };
  const other = version === "v3" ? finding.cvssV2 : finding.cvssV3;
  if (other > 0) return { value: other, used: version === "v3" ? "v2" : "v3" };
  return { value: 0, used: null };
}

type ScoreView = "v3" | "v2" | "vpr";

function CvssToggle({
  version,
  onChange,
}: {
  version: ScoreView;
  onChange: (v: ScoreView) => void;
}) {
  return (
    <div className="inline-flex items-center gap-1 rounded-2xl border border-zinc-800 bg-[#090909] p-1">
      <span className="px-2 text-[11px] uppercase tracking-[0.18em] text-zinc-500">
        Score
      </span>
      {(["v3", "v2", "vpr"] as ScoreView[]).map((v) => (
        <button
          key={v}
          onClick={() => onChange(v)}
          className={[
            "rounded-xl px-3 py-1.5 text-sm uppercase transition",
            version === v
              ? "bg-[rgba(179,14,20,0.20)] text-white"
              : "text-zinc-400 hover:text-zinc-200",
          ].join(" ")}
        >
          {v === "vpr" ? "VPR" : v}
        </button>
      ))}
    </div>
  );
}

export default function VulnFindingsPage() {
  const searchParams = useSearchParams();
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [kind, setKind] = useState<"vuln" | "osint" | "all">("vuln");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [connectorFilter, setConnectorFilter] = useState("All");
  const [companyFilter, setCompanyFilter] = useState(
    searchParams.get("company") ?? "All",
  );
  const [companies, setCompanies] = useState<{ id: string; name: string }[]>([]);
  const [exploitOnly, setExploitOnly] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [cvssVersion, setCvssVersion] = useState<ScoreView>("v3");
  const [focusId, setFocusId] = useState<string | null>(
    searchParams.get("focus"),
  );
  // Deep-linked finding fetched directly when it isn't in the current page.
  const [focusFetched, setFocusFetched] = useState<FindingRow | null>(null);
  const [assigneeDraft, setAssigneeDraft] = useState("");
  const [patchError, setPatchError] = useState<string | null>(null);
  // Bulk remediation selection + request outcome.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [remediationBusy, setRemediationBusy] = useState(false);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const [remediationResult, setRemediationResult] =
    useState<RemediationResult | null>(null);
  // Monotonic request id — a slow older response must never overwrite a newer one.
  const loadSeq = useRef(0);

  // Debounce the search box so we don't refetch on every keystroke.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Any filter change starts back at the first page and drops the selection —
  // rows selected under different filters shouldn't feed a bulk action.
  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
  }, [
    kind,
    debouncedSearch,
    severityFilter,
    statusFilter,
    connectorFilter,
    companyFilter,
    exploitOnly,
    overdueOnly,
  ]);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    const params = new URLSearchParams({
      kind,
      limit: String(PAGE_SIZE),
      offset: String(offset),
    });
    if (companyFilter !== "All") params.set("companyId", companyFilter);
    if (severityFilter !== "All") params.set("severity", severityFilter);
    if (statusFilter !== "All") params.set("status", statusFilter);
    if (connectorFilter !== "All") params.set("connector", connectorFilter);
    if (exploitOnly) params.set("exploit", "1");
    if (overdueOnly) params.set("overdue", "1");
    if (debouncedSearch.trim()) params.set("q", debouncedSearch.trim());
    try {
      const res = await fetch(`/api/findings?${params.toString()}`, {
        cache: "no-store",
      });
      const json = await res.json();
      if (seq !== loadSeq.current) return; // superseded by a newer request
      const nextTotal = json.total ?? 0;
      setFindings(json.findings ?? []);
      setTotal(nextTotal);
      // If the data shrank under us, snap back to the last valid page.
      setOffset((prev) =>
        prev > 0 && prev >= nextTotal
          ? Math.max(0, Math.floor(Math.max(nextTotal - 1, 0) / PAGE_SIZE) * PAGE_SIZE)
          : prev,
      );
    } catch {
      // keep last snapshot
    }
  }, [
    kind,
    offset,
    debouncedSearch,
    severityFilter,
    statusFilter,
    connectorFilter,
    companyFilter,
    exploitOnly,
    overdueOnly,
  ]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
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
  }, []);

  const focusInPage = useMemo(
    () => findings.find((f) => f.id === focusId) ?? null,
    [findings, focusId],
  );
  const focus =
    focusInPage ??
    (focusFetched && focusFetched.id === focusId ? focusFetched : null);

  // ?focus=<id> deep link: the finding may not be on the current page — fetch
  // it directly so the detail panel still opens.
  useEffect(() => {
    if (!focusId || focusInPage) return;
    let cancelled = false;
    void fetch(`/api/findings/${focusId}`, { cache: "no-store" })
      .then((res) => (res.ok ? res.json() : null))
      .then((json) => {
        if (!cancelled && json?.finding) setFocusFetched(json.finding);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [focusId, focusInPage]);

  useEffect(() => {
    setAssigneeDraft(focus?.assignee ?? "");
    setPatchError(null);
  }, [focus?.id, focus?.assignee]);

  async function patchFinding(
    id: string,
    patch: { status?: FindingStatus; assignee?: string | null },
  ) {
    setPatchError(null);
    try {
      const res = await fetch(`/api/findings/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        setPatchError(json.error ?? `Update failed (HTTP ${res.status}).`);
        return;
      }
      const json = await res.json();
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? json.finding : f)),
      );
      setFocusFetched((prev) =>
        prev && prev.id === id ? json.finding : prev,
      );
    } catch {
      setPatchError("Failed to reach the API — change not saved.");
    }
  }

  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else if (next.size < SELECTION_CAP) next.add(id);
      return next;
    });
  }

  const pageAllSelected =
    findings.length > 0 && findings.every((f) => selected.has(f.id));

  function togglePageSelected() {
    setSelected((prev) => {
      const next = new Set(prev);
      if (pageAllSelected) {
        for (const f of findings) next.delete(f.id);
      } else {
        for (const f of findings) {
          if (next.size >= SELECTION_CAP) break;
          next.add(f.id);
        }
      }
      return next;
    });
  }

  const companyName = useCallback(
    (id: string) => companies.find((c) => c.id === id)?.name ?? id,
    [companies],
  );

  async function requestRemediation() {
    if (selected.size === 0 || remediationBusy) return;
    setRemediationBusy(true);
    setRemediationError(null);
    setRemediationResult(null);
    try {
      const res = await fetch("/api/remediation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findingIds: Array.from(selected) }),
      });
      if (!res.ok) {
        const json = await res.json().catch(() => ({}));
        setRemediationError(
          json.error ?? `Remediation request failed (HTTP ${res.status}).`,
        );
        return;
      }
      const json = await res.json();
      setRemediationResult({
        sent: json.sent ?? [],
        skipped: json.skipped ?? [],
      });
      setSelected(new Set());
      void load(); // statuses may have moved to In Remediation
    } catch {
      setRemediationError("Failed to reach the API — nothing was sent.");
    } finally {
      setRemediationBusy(false);
    }
  }

  return (
    <VulnShell
      eyebrow="Findings"
      title="Finding triage"
      subtitle="Vulnerability-scan findings (CVE-based) are kept separate from OSINT / attack-surface findings. Filter, assign, and track through remediation."
    >
      <div className="mb-4 inline-flex rounded-xl border border-zinc-800 bg-[#0b0b0b] p-1">
        {(
          [
            { id: "vuln", label: "Vulnerabilities" },
            { id: "osint", label: "Attack Surface (OSINT)" },
            { id: "all", label: "All" },
          ] as const
        ).map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setKind(t.id)}
            className={`rounded-lg px-4 py-1.5 text-sm font-medium transition ${
              kind === t.id
                ? "bg-[rgba(179,14,20,0.16)] text-[#ff4d57]"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <PanelCard eyebrow="Filters">
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1.3fr)_180px_150px_180px_170px_150px_120px_130px]">
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
          <button
            onClick={() => setOverdueOnly((prev) => !prev)}
            className={[
              "flex h-[52px] items-center justify-center gap-2 rounded-2xl border px-4 text-sm transition",
              overdueOnly
                ? "border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] text-white"
                : "border-zinc-800 bg-[#0b0b0b] text-zinc-300 hover:bg-[#101010]",
            ].join(" ")}
          >
            Overdue
          </button>
          <button onClick={() => void load()} className={ghostButtonClass}>
            <RefreshCcw size={16} className="text-zinc-400" />
            Refresh
          </button>
        </div>
      </PanelCard>

      <PanelCard
        eyebrow="Findings"
        description={
          total > 0
            ? `Showing ${offset + 1}–${offset + findings.length} of ${total} findings`
            : "0 findings"
        }
        actions={<CvssToggle version={cvssVersion} onChange={setCvssVersion} />}
      >
        {selected.size > 0 ? (
          <div className="mb-4 flex flex-wrap items-center gap-3 rounded-2xl border border-[rgba(179,14,20,0.30)] bg-[rgba(179,14,20,0.08)] px-4 py-3">
            <span className="text-sm font-medium text-white">
              {selected.size} selected
            </span>
            {selected.size >= SELECTION_CAP ? (
              <span className="text-xs text-amber-300">
                Selection capped at {SELECTION_CAP} findings per request.
              </span>
            ) : null}
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => void requestRemediation()}
                disabled={remediationBusy}
                className="h-[44px] rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] px-5 text-sm font-medium text-white transition hover:bg-[rgba(179,14,20,0.28)] disabled:opacity-50"
              >
                {remediationBusy
                  ? "Sending…"
                  : `Request remediation (${selected.size})`}
              </button>
              <button
                onClick={() => setSelected(new Set())}
                className={`${ghostButtonClass} h-[44px]`}
              >
                Clear
              </button>
            </div>
            {remediationError ? (
              <p className="w-full text-xs text-[#ff4d57]">{remediationError}</p>
            ) : null}
          </div>
        ) : remediationError ? (
          <p className="mb-4 text-xs text-[#ff4d57]">{remediationError}</p>
        ) : null}

        {remediationResult ? (
          <div className="mb-4 space-y-1.5 rounded-2xl border border-zinc-800 bg-[#090909] px-4 py-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs uppercase tracking-[0.2em] text-zinc-500">
                Remediation request results
              </span>
              <button
                onClick={() => setRemediationResult(null)}
                className="text-xs text-zinc-500 transition hover:text-white"
              >
                Dismiss
              </button>
            </div>
            {remediationResult.sent.map((s) => (
              <div key={`sent-${s.companyId}`} className="text-sm text-emerald-300">
                {companyName(s.companyId)} — sent for {s.count} finding
                {s.count === 1 ? "" : "s"}
              </div>
            ))}
            {remediationResult.skipped.map((s) => (
              <div key={`skip-${s.companyId}`} className="text-sm text-amber-300">
                {companyName(s.companyId)} — skipped: {s.reason}
              </div>
            ))}
            {remediationResult.sent.length === 0 &&
            remediationResult.skipped.length === 0 ? (
              <div className="text-sm text-zinc-500">Nothing to send.</div>
            ) : null}
          </div>
        ) : null}

        <div className="overflow-hidden rounded-[24px] border border-[rgba(179,14,20,0.12)] bg-[#040404]">
          <div className="grid grid-cols-[28px_100px_1.9fr_1.1fr_120px_80px_100px_130px_110px_80px] items-center gap-4 border-b border-zinc-900 px-5 py-4 text-xs uppercase tracking-[0.2em] text-zinc-500">
            <div>
              <input
                type="checkbox"
                checked={pageAllSelected}
                onChange={togglePageSelected}
                aria-label="Select all findings on this page"
                className="h-4 w-4 cursor-pointer rounded border-zinc-700 bg-[#0b0b0b] accent-[#b30e14]"
              />
            </div>
            <div>ID</div>
            <div>Finding</div>
            <div>Asset</div>
            <div>Real risk</div>
            <div>{cvssVersion === "vpr" ? "VPR" : `CVSS ${cvssVersion}`}</div>
            <div>Severity</div>
            <div>Status</div>
            <div>Due</div>
            <div>Age</div>
          </div>
          <div className={`max-h-[680px] ${scrollAreaClass}`}>
            {findings.map((finding) => (
              <div
                key={finding.id}
                role="button"
                tabIndex={0}
                onClick={() => setFocusId(finding.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setFocusId(finding.id);
                  }
                }}
                className={[
                  "grid w-full cursor-pointer grid-cols-[28px_100px_1.9fr_1.1fr_120px_80px_100px_130px_110px_80px] items-center gap-4 border-b border-zinc-900/70 px-5 py-4 text-left transition last:border-b-0 hover:bg-[#0a0a0a]",
                  focusId === finding.id ? "bg-[rgba(179,14,20,0.06)]" : "",
                ].join(" ")}
              >
                <div onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selected.has(finding.id)}
                    onChange={() => toggleSelected(finding.id)}
                    onKeyDown={(e) => e.stopPropagation()}
                    aria-label={`Select ${finding.id}`}
                    className="h-4 w-4 cursor-pointer rounded border-zinc-700 bg-[#0b0b0b] accent-[#b30e14]"
                  />
                </div>
                <div className="text-sm font-medium text-[#ff4d57]">
                  {finding.id}
                </div>
                <div className="min-w-0">
                  <div className="truncate font-medium text-white">
                    {finding.title}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                    <span className="text-[#ff8f96]">{finding.cve}</span>
                    {finding.kev ? (
                      <span className="rounded-full border border-[rgba(179,14,20,0.55)] bg-[rgba(179,14,20,0.16)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-[#ff4d57]">
                        KEV
                      </span>
                    ) : null}
                    {finding.ransomware ? (
                      <span
                        title="CISA KEV: used in ransomware campaigns"
                        className="rounded-full border border-fuchsia-800/70 bg-[rgba(217,70,239,0.14)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-fuchsia-300"
                      >
                        Ransomware
                      </span>
                    ) : null}
                    {finding.exploitAvailable ? (
                      <span className="rounded-full border border-orange-900/60 bg-[rgba(245,110,35,0.12)] px-2 py-0.5 text-[10px] uppercase tracking-[0.14em] text-orange-300">
                        Exploit
                      </span>
                    ) : null}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="truncate text-sm text-zinc-300">
                    {finding.asset}
                  </div>
                  <div
                    className={`mt-1 text-xs ${exposureClass[finding.assetExposure] ?? "text-zinc-500"}`}
                  >
                    {finding.assetExposure} · {finding.assetCriticality}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className="text-lg font-semibold"
                    style={{ color: riskColor(finding.realRisk) }}
                  >
                    {finding.realRisk}
                  </span>
                  <Pill className={riskPriorityClass[finding.riskPriority]}>
                    {finding.riskPriority}
                  </Pill>
                </div>
                <div className="text-sm text-zinc-300">
                  {(() => {
                    if (cvssVersion === "vpr") {
                      return finding.vpr > 0 ? finding.vpr.toFixed(1) : "—";
                    }
                    const { value, used } = cvssFor(finding, cvssVersion);
                    if (value <= 0) return "—";
                    return (
                      <span>
                        {value.toFixed(1)}
                        {used && used !== cvssVersion ? (
                          <span className="ml-1 text-[10px] text-zinc-600">
                            {used}
                          </span>
                        ) : null}
                      </span>
                    );
                  })()}
                </div>
                <div>
                  <Pill className={severityClass[finding.severity]}>
                    {finding.severity}
                  </Pill>
                </div>
                <div>
                  <Pill className={findingStatusClass[finding.status]}>
                    {finding.status}
                  </Pill>
                </div>
                <div>
                  <DuePill dueAt={finding.dueAt} overdue={finding.overdue} />
                </div>
                <div className="text-sm text-zinc-400">
                  {formatAge(finding.firstSeen)}
                </div>
              </div>
            ))}
            {findings.length === 0 ? (
              <div className="px-5 py-12 text-center text-sm text-zinc-500">
                No findings match the current filters.
              </div>
            ) : null}
          </div>
        </div>
        <div className="mt-4 flex items-center justify-between gap-4">
          <span className="text-sm text-zinc-500">
            {total > 0
              ? `Showing ${offset + 1}–${offset + findings.length} of ${total}`
              : "Showing 0 of 0"}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={offset === 0}
              onClick={() => setOffset((prev) => Math.max(0, prev - PAGE_SIZE))}
              className={`${ghostButtonClass} h-[44px] disabled:opacity-40`}
            >
              <ChevronLeft size={16} className="text-zinc-400" />
              Previous
            </button>
            <button
              type="button"
              disabled={offset + findings.length >= total}
              onClick={() => setOffset((prev) => prev + PAGE_SIZE)}
              className={`${ghostButtonClass} h-[44px] disabled:opacity-40`}
            >
              Next
              <ChevronRight size={16} className="text-zinc-400" />
            </button>
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
                {focus.kev ? (
                  <Pill className="border border-[rgba(179,14,20,0.55)] bg-[rgba(179,14,20,0.16)] text-[#ff4d57]">
                    KEV · exploited in the wild
                  </Pill>
                ) : null}
                {focus.exploitAvailable ? (
                  <Pill className="border border-orange-900/60 bg-[rgba(245,110,35,0.12)] text-orange-300">
                    Exploit available
                  </Pill>
                ) : null}
                {focus.overdue || focus.dueAt ? (
                  <DuePill dueAt={focus.dueAt} overdue={focus.overdue} />
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
            <div className="rounded-2xl border border-[rgba(179,14,20,0.20)] bg-[linear-gradient(180deg,#0c0708,#070707)] p-5">
              <div className="flex items-center justify-between">
                <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">
                  Real risk
                </div>
                <Pill className={riskPriorityClass[focus.riskPriority]}>
                  {focus.riskPriority}
                </Pill>
              </div>
              <div className="mt-2 flex items-end gap-3">
                <span
                  className="text-5xl font-semibold tracking-[-0.04em]"
                  style={{ color: riskColor(focus.realRisk) }}
                >
                  {focus.realRisk}
                </span>
                <span className="mb-1 text-sm text-zinc-500">/ 100</span>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                <RiskFactor
                  label="Base CVSS"
                  value={(focus.cvssV3 || focus.cvssV2).toFixed(1)}
                />
                <RiskFactor
                  label="Exploited in wild"
                  value={focus.kev ? "Yes (CISA KEV)" : "Not listed"}
                  hot={focus.kev}
                />
                <RiskFactor
                  label="EPSS"
                  value={`${Math.round(focus.epss * 100)}%`}
                />
                <RiskFactor
                  label="Public exploit"
                  value={focus.exploitAvailable ? "Available" : "None"}
                  hot={focus.exploitAvailable}
                />
                <RiskFactor
                  label="Asset exposure"
                  value={focus.assetExposure}
                  hot={focus.assetExposure === "Internet-facing"}
                />
                <RiskFactor
                  label="Asset criticality"
                  value={focus.assetCriticality}
                  hot={focus.assetCriticality === "Crown Jewel"}
                />
              </div>
              <p className="mt-4 text-xs leading-relaxed text-zinc-500">
                Base CVSS adjusted for real-world exploitation (KEV, EPSS,
                public exploit) and the affected asset&apos;s exposure and
                business criticality.{" "}
                <span className="text-zinc-400">
                  Environment context:{" "}
                  {focus.assetSource === "tidal"
                    ? "Tidal.io inventory"
                    : focus.assetSource === "intune"
                      ? "Intune device inventory"
                      : focus.assetSource === "crowdstrike"
                        ? "CrowdStrike host inventory"
                        : focus.assetSource === "manual"
                          ? "manual inventory"
                          : "inferred from hostname"}
                  .
                </span>
              </p>
            </div>

            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm">
              <Detail label="Company" value={focus.companyName} />
              <Detail label="Asset" value={focus.asset} />
              <Detail label="Port" value={focus.port} />
              <Detail
                label="CVSS v3"
                value={focus.cvssV3 > 0 ? focus.cvssV3.toFixed(1) : "—"}
              />
              <Detail
                label="CVSS v2"
                value={focus.cvssV2 > 0 ? focus.cvssV2.toFixed(1) : "—"}
              />
              <Detail
                label="VPR (Tenable)"
                value={focus.vpr > 0 ? focus.vpr.toFixed(1) : "—"}
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
              <Detail
                label="Remediation due"
                value={
                  focus.dueAt ? (
                    <span className={focus.overdue ? "text-[#ff4d57]" : undefined}>
                      {formatDateTime(focus.dueAt)}
                      {focus.overdue ? " · overdue" : ""}
                    </span>
                  ) : (
                    "—"
                  )
                }
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
                {patchError ? (
                  <p className="text-xs text-[#ff4d57]">{patchError}</p>
                ) : null}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </VulnShell>
  );
}

// Compact due-state pill: red "Overdue Xd", amber "Due in Xd" when the window
// is a week or less, muted zinc otherwise. Renders an em dash when no SLA due
// date applies (already resolved, Info severity, backend not deployed yet).
function DuePill({
  dueAt,
  overdue,
}: {
  dueAt?: string | null;
  overdue?: boolean;
}) {
  if (overdue) {
    const days = dueAt
      ? Math.max(0, Math.floor((Date.now() - new Date(dueAt).getTime()) / 86_400_000))
      : null;
    return (
      <Pill className="border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] text-[#ff4d57]">
        {days !== null ? `Overdue ${days}d` : "Overdue"}
      </Pill>
    );
  }
  if (!dueAt) return <span className="text-sm text-zinc-600">—</span>;
  const days = Math.max(
    0,
    Math.ceil((new Date(dueAt).getTime() - Date.now()) / 86_400_000),
  );
  return (
    <Pill
      className={
        days <= 7
          ? "border border-amber-900/60 bg-[rgba(245,166,35,0.10)] text-amber-300"
          : "border border-zinc-800 bg-zinc-900 text-zinc-400"
      }
    >
      Due in {days}d
    </Pill>
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

function RiskFactor({
  label,
  value,
  hot,
}: {
  label: string;
  value: React.ReactNode;
  hot?: boolean;
}) {
  return (
    <div className="rounded-xl border border-zinc-900 bg-[#0a0a0a] px-3 py-2">
      <div className="text-[10px] uppercase tracking-[0.16em] text-zinc-600">
        {label}
      </div>
      <div className={hot ? "mt-1 font-medium text-[#ff4d57]" : "mt-1 text-zinc-200"}>
        {value}
      </div>
    </div>
  );
}
