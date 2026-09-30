"use client";
import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import styles from "./QueryDashboard.module.css";

type FindingRisk = {
  id: string; tenantKey: string; companyId: string; cve: string; hostname: string; severity: string;
  riskScore: number; technicalScore: number; exploitLikelihoodScore: number; threatActivityScore: number;
  assetContextScore: number; additionalContextScore: number; reasons: string[];
  calculatedSwath: number; effectiveSwath: number; swathOverrideBy: string | null; swathOverrideReason: string | null;
  epssProbability: number | null; epssPercentile: number | null; cisaKev: boolean; knownExploit: boolean;
  activeExploitation: boolean; ransomwareAssociation: boolean; internetExposed: boolean; assetCriticality: string;
  verificationStatus: string; verifiedAt: string | null; lastSeen: string;
};

type RiskSummary = {
  totalOpenRisk: number; criticalRiskCount: number; swath1Open: number; swath2Open: number;
  kevOpen: number; internetFacingCriticalRisk: number; verifiedRemediations: number; awaitingVerification: number;
};

const SWATH_STYLE: Record<number, { label: string; className: string }> = {
  1: { label: "Swath 1 · Immediate", className: "border-[#ff4d57] bg-[rgba(179,14,20,0.16)] text-[#ff8f96]" },
  2: { label: "Swath 2 · High", className: "border-amber-500 bg-amber-950/30 text-amber-300" },
  3: { label: "Swath 3 · Medium", className: "border-sky-600 bg-sky-950/30 text-sky-300" },
  4: { label: "Swath 4 · Lower", className: "border-zinc-600 bg-zinc-900 text-zinc-400" },
};

const VERIFICATION_LABEL: Record<string, string> = {
  detected: "Detected", ticket_created: "Ticket created", pending_verification: "Pending verification",
  verified_remediated: "Verified remediated", reopened: "Reopened",
};

function SwathBadge({ swath, overridden }: { swath: number; overridden: boolean }) {
  const style = SWATH_STYLE[swath] ?? SWATH_STYLE[4];
  return <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${style.className}`}>
    {style.label}{overridden && <span title="Manually overridden">*</span>}
  </span>;
}

function ScoreExplain({ row }: { row: FindingRisk }) {
  return <div className="mt-2 rounded-lg border border-zinc-800 bg-black/40 p-3 text-xs text-zinc-300">
    <p className="text-sm font-semibold text-white">Risk Score: {row.riskScore} / 1000 — why this is risky</p>
    <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-5">
      <span>Technical: <b className="text-white">{row.technicalScore}</b></span>
      <span>Exploit Likelihood: <b className="text-white">{row.exploitLikelihoodScore}</b></span>
      <span>Threat Activity: <b className="text-white">{row.threatActivityScore}</b></span>
      <span>Asset Context: <b className="text-white">{row.assetContextScore}</b></span>
      <span>Additional: <b className="text-white">{row.additionalContextScore}</b></span>
    </div>
    {row.reasons.length > 0 && <ul className="mt-2 list-disc space-y-0.5 pl-4">{row.reasons.map((r) => <li key={r}>{r}</li>)}</ul>}
    {row.swathOverrideBy && <p className="mt-2 text-amber-300">Swath manually overridden by {row.swathOverrideBy}{row.swathOverrideReason ? `: ${row.swathOverrideReason}` : ""}</p>}
  </div>;
}

function OverrideForm({ row, onDone }: { row: FindingRisk; onDone: () => void }) {
  const [swath, setSwath] = useState(String(row.effectiveSwath));
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit() {
    setBusy(true); setError("");
    try {
      await dashboardRequest(`risk/${row.id}/override-swath`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ swath: Number(swath), reason }) });
      onDone();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save the override."); }
    finally { setBusy(false); }
  }
  return <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-zinc-800 bg-black/40 p-2 text-xs">
    <select value={swath} onChange={(e) => setSwath(e.target.value)} className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-zinc-100">
      {[1, 2, 3, 4].map((s) => <option key={s} value={s}>Swath {s}</option>)}
    </select>
    <input type="text" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (required)" className="min-w-[10rem] flex-1 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-zinc-100 placeholder:text-zinc-600" />
    <button type="button" className={styles.button} disabled={busy || !reason.trim()} onClick={() => void submit()}>{busy ? "Saving…" : "Override"}</button>
    {error && <span className="text-[#ff8f96]">{error}</span>}
  </div>;
}

function RiskRow({ row, onChanged }: { row: FindingRisk; onChanged: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [overriding, setOverriding] = useState(false);
  return <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="text-lg font-bold text-white hover:underline" onClick={() => setExpanded((v) => !v)} title="Click to explain this score">{row.riskScore}</button>
          <SwathBadge swath={row.effectiveSwath} overridden={Boolean(row.swathOverrideBy)} />
          {row.cisaKev && <span className="rounded-full border border-[#ff4d57] bg-[rgba(179,14,20,0.14)] px-2 py-0.5 text-[10px] font-semibold uppercase text-[#ff8f96]">CISA KEV</span>}
          {row.internetExposed && <span className="rounded-full border border-sky-600 bg-sky-950/30 px-2 py-0.5 text-[10px] font-semibold uppercase text-sky-300">Internet-facing</span>}
        </div>
        <p className="mt-1 truncate text-sm text-zinc-200">{row.cve} — {row.hostname || row.tenantKey}</p>
        <p className="mt-0.5 text-xs text-zinc-500">{row.assetCriticality} criticality · {VERIFICATION_LABEL[row.verificationStatus] ?? row.verificationStatus}{row.epssProbability != null && ` · EPSS ${Math.round(row.epssProbability * 100)}%`}</p>
      </div>
      <button type="button" className={styles.button} onClick={() => setOverriding((v) => !v)}>Override Swath</button>
    </div>
    {expanded && <ScoreExplain row={row} />}
    {overriding && <OverrideForm row={row} onDone={() => { setOverriding(false); onChanged(); }} />}
  </div>;
}

export default function RiskDashboard({ companyId }: { companyId?: string }) {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [rows, setRows] = useState<FindingRisk[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState("");
  const [checkingJob, setCheckingJob] = useState(false);
  const [jobStatus, setJobStatus] = useState("");
  const [swathFilter, setSwathFilter] = useState<number | null>(null);

  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const qs = companyId ? `?companyId=${encodeURIComponent(companyId)}` : "";
      const [summaryResult, topResult] = await Promise.all([
        dashboardRequest<RiskSummary>(`risk/summary${qs}`),
        dashboardRequest<{ rows: FindingRisk[]; total: number }>(`risk/top${qs}${qs ? "&" : "?"}limit=100${swathFilter ? `&swath=${swathFilter}` : ""}`),
      ]);
      setSummary(summaryResult); setRows(topResult.rows);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load risk data."); }
    finally { setLoading(false); }
  }, [companyId, swathFilter]);
  useEffect(() => { void reload(); }, [reload]);

  async function refreshNow() {
    setRefreshing(true); setRefreshResult(""); setError("");
    try {
      const result = await dashboardRequest<{ started: boolean }>("risk/refresh", { method: "POST" });
      setRefreshResult(result.started ? "Started -- refreshing CISA KEV/EPSS and rescoring can take a few minutes. Click Refresh shortly to see results." : "Already running from a previous trigger.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not start the risk refresh."); }
    finally { setRefreshing(false); }
  }
  async function checkJob() {
    setCheckingJob(true); setJobStatus(""); setError("");
    try {
      const result = await dashboardRequest<{ run: { status: string; result: unknown; error: string | null; startedAt: string; finishedAt: string | null } | null }>("patch-group-tickets/job-status?job=risk-refresh");
      const run = result.run;
      if (!run) { setJobStatus("Risk refresh: never run yet."); return; }
      const when = run.finishedAt ? new Date(run.finishedAt).toLocaleString() : `started ${new Date(run.startedAt).toLocaleString()}`;
      setJobStatus(run.status === "running" ? `Risk refresh: still running (${when}).` : run.status === "failed" ? `Risk refresh: failed at ${when} -- ${run.error}` : `Risk refresh: finished ${when} -- ${JSON.stringify(run.result)}`);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not check job status."); }
    finally { setCheckingJob(false); }
  }

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5" aria-label="Risk-based vulnerability prioritization">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <div>
        <p className="text-xs uppercase tracking-[0.25em] text-red-500">Risk-Based Vulnerability Management</p>
        <h2 className="mt-2 text-lg text-zinc-100">Top Risk</h2>
      </div>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={styles.button} disabled={refreshing} onClick={() => void refreshNow()}>{refreshing ? "Starting…" : "Refresh risk data now"}</button>
        <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
      </div>
    </div>
    {refreshResult && <p role="status" className={`${styles.resultNote} mt-1`}>{refreshResult} <button type="button" className="underline" disabled={checkingJob} onClick={() => void checkJob()}>{checkingJob ? "Checking…" : "Check status"}</button></p>}
    {jobStatus && <p role="status" className={`${styles.resultNote} mt-1 font-medium`}>{jobStatus}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}

    {summary && <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{summary.totalOpenRisk.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Total Open Risk</div></div>
      <div className="rounded-xl border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] p-3"><div className="text-2xl font-semibold text-[#ff8f96]">{summary.criticalRiskCount.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Critical Risk (800+)</div></div>
      <button type="button" onClick={() => setSwathFilter((v) => v === 1 ? null : 1)} className={`rounded-xl border p-3 text-left transition-colors ${swathFilter === 1 ? "border-[#ff8f96] bg-[rgba(179,14,20,0.16)]" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700"}`}>
        <div className="text-2xl font-semibold text-white">{summary.swath1Open.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Swath 1 Open</div></button>
      <button type="button" onClick={() => setSwathFilter((v) => v === 2 ? null : 2)} className={`rounded-xl border p-3 text-left transition-colors ${swathFilter === 2 ? "border-amber-400 bg-amber-950/30" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700"}`}>
        <div className="text-2xl font-semibold text-white">{summary.swath2Open.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Swath 2 Open</div></button>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{summary.kevOpen.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">CISA KEV Open</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{summary.internetFacingCriticalRisk.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Internet-Facing Critical</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-emerald-300">{summary.verifiedRemediations.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Verified Remediations</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-amber-300">{summary.awaitingVerification.toLocaleString()}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Awaiting Verification</div></div>
    </div>}

    <p className={`${styles.resultNote} mt-3`}>Sorted by Risk Score, highest first{swathFilter ? ` · filtered to Swath ${swathFilter}` : ""}. Ticket priority reconciles to Swath automatically unless a person has set it by hand.</p>
    <div className="mt-3 space-y-2">
      {rows.map((row) => <RiskRow key={row.id} row={row} onChanged={() => void reload()} />)}
      {!rows.length && !loading && <p className={styles.resultNote}>No scored findings yet -- risk scoring runs on its own schedule once CrowdStrike Spotlight data is imported, or click &quot;Refresh risk data now&quot;.</p>}
    </div>
  </section>;
}
