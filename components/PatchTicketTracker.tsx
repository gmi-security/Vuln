"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { ageDays, patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import { slaDaysFor } from "@/lib/vuln-sla";
import type { SlaSettings } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

type Row = { id: string; scope: string; cves: string[]; row: PatchGroupTicketSummary };

type Bucket = "cut-open" | "cut-closed" | "attention" | "draft";
function stateBucket(state: string, ticketId: number | null, closed: boolean): Bucket {
  if (ticketId) return closed ? "cut-closed" : "cut-open";
  if (state === "failed" || state === "uncertain") return "attention";
  return "draft";
}
const BUCKET_BADGE: Record<Bucket, { label: string; className: string }> = {
  "cut-open": { label: "Open", className: "border-emerald-800/60 bg-emerald-950/30 text-emerald-300" },
  "cut-closed": { label: "Closed", className: "border-zinc-700 bg-zinc-900 text-zinc-300" },
  attention: { label: "Needs attention", className: "border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.12)] text-[#ff8f96]" },
  draft: { label: "Draft", className: "border-amber-800/60 bg-amber-950/20 text-amber-300" },
};
function StatusBadge({ bucket }: { bucket: Bucket }) {
  const { label, className } = BUCKET_BADGE[bucket];
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${className}`}>{label}</span>;
}
// slaDays is the org's real per-severity SLA (Settings > SLA) for this
// ticket's worst CVE severity -- null only until it's loaded.
function trackerAgeBadge(row: PatchGroupTicketSummary, slaDays: number | null) {
  const days = ageDays(row.preparedAt);
  const openTicket = Boolean(row.ticketId) && !row.closed;
  if (!openTicket || slaDays === null) return <span className="text-zinc-500">{days}d</span>;
  const cls = days >= slaDays ? "font-semibold text-[#ff8f96]" : days >= slaDays * 0.7 ? "text-amber-400" : "text-zinc-400";
  return <span className={cls}>{days}d{days >= slaDays ? ` · overdue (SLA ${slaDays}d)` : ""}</span>;
}

export default function PatchTicketTracker({ companyId, sla }: { companyId: string; sla: SlaSettings | null }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [more, setMore] = useState(false);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoCreating, setAutoCreating] = useState(false);
  const [autoCreateResult, setAutoCreateResult] = useState("");
  const [validating, setValidating] = useState(false);
  const [validateResult, setValidateResult] = useState("");
  const [findingUntracked, setFindingUntracked] = useState(false);
  const [untracked, setUntracked] = useState<{ id: number; summary: string; status: string; closed: boolean; url: string }[] | null>(null);
  const [adopting, setAdopting] = useState(false);
  const [adoptResult, setAdoptResult] = useState("");
  const [abandoning, setAbandoning] = useState(false);
  const [abandonResult, setAbandonResult] = useState("");
  const [recutting, setRecutting] = useState(false);
  const [recutResult, setRecutResult] = useState("");
  const [checkingJob, setCheckingJob] = useState("");
  const [jobStatus, setJobStatus] = useState("");
  const [bucketFilter, setBucketFilter] = useState<Bucket | "all">("all");
  const [search, setSearch] = useState("");

  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const requests: PatchGroupTicketSummary[] = [];
      let page = 1, hasMore = true;
      let matchingTotal = 0;
      while (hasMore && page <= 10_000) {
        const data = await dashboardRequest<{ requests: PatchGroupTicketSummary[]; more: boolean; total: number }>(`patch-group-tickets?companyId=${encodeURIComponent(companyId)}&page=${page}`);
        requests.push(...data.requests);
        matchingTotal = data.total;
        hasMore = data.more;
        page++;
      }
      const combined: Row[] = requests.map(row => ({ id: row.id,
        scope: row.cves.length === 1 ? row.cves[0] : `${(row.remediationTitle || "Remediation").slice(0, 48)} · ${row.cves.length} CVEs`, cves: row.cves, row }))
        .sort((a, b) => new Date(b.row.preparedAt).getTime() - new Date(a.row.preparedAt).getTime());
      setRows(combined); setMore(hasMore); setTotal(matchingTotal);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load the ticket tracker."); }
    finally { setLoading(false); }
  }, [companyId]);
  useEffect(() => { void reload(); }, [reload]);

  async function runAutoCreateNow() {
    setAutoCreating(true); setAutoCreateResult(""); setError("");
    try {
      const result = await dashboardRequest<{ checked: number; created: number; errors: number; paused?: boolean; priorityBackfill: { checked: number; updated: number; errors: number } }>("patch-group-tickets/auto-create", { method: "POST" });
      const p = result.priorityBackfill;
      const priorityNote = p.checked ? ` Priority backfill: updated ${p.updated} of ${p.checked} existing ticket${p.checked === 1 ? "" : "s"}${p.errors ? ` · ${p.errors} failed` : ""}.` : "";
      const creationNote = result.paused
        ? "Auto-create is paused for Atlas -- no new tickets until this is turned back on."
        : `Checked ${result.checked} eligible draft${result.checked === 1 ? "" : "s"} · created ${result.created}${result.errors ? ` · ${result.errors} failed` : ""}.`;
      setAutoCreateResult(`${creationNote}${priorityNote}`);
      await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not run auto-create."); }
    finally { setAutoCreating(false); }
  }

  // A full pass can mean a live CrowdStrike re-collection for every closed
  // ticket -- some of this pilot's consolidated tickets carry 40+ CVEs each
  // -- which can run for minutes, well past this app's 20-second request
  // timeout. This only starts the pass (the same one the 5-minute background
  // scheduler runs) and returns right away; it does not wait for or report
  // counts. Check the table below (or click Refresh) after a bit to see the
  // result -- per-ticket failures show as a note under that ticket's state.
  async function runValidateClosuresNow() {
    setValidating(true); setValidateResult(""); setError("");
    try {
      const result = await dashboardRequest<{ started: boolean }>("patch-group-tickets/validate-closures", { method: "POST" });
      setValidateResult(result.started
        ? "Started -- this can take a few minutes for tickets with many CVEs. Click Refresh shortly to see results."
        : "Already running from a previous trigger -- that pass covers this too. Click Refresh shortly to see results.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not start closure validation."); }
    finally { setValidating(false); }
  }

  // A ticket created by pasting draft text directly into ConnectWise, rather
  // than through this app's own "Create ticket" action, has no tracked row
  // and is invisible to every automated check above -- this diffs the live
  // ConnectWise board against what's tracked so those can be found and
  // handled by hand instead of discovered one at a time.
  async function findUntrackedNow() {
    setFindingUntracked(true); setError("");
    try {
      const result = await dashboardRequest<{ tickets: { id: number; summary: string; status: string; closed: boolean; url: string }[] }>("patch-group-tickets/untracked");
      setUntracked(result.tickets);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not check for untracked tickets."); }
    finally { setFindingUntracked(false); }
  }

  // A manually-pasted ticket's attached CSV is named after the exact draft
  // row it came from (a UUID) -- an unambiguous link, not a guess. This
  // relinks each one so it becomes a normal tracked ticket, visible to
  // auto-create/priority/closure-validation from then on.
  async function adoptUntrackedNow() {
    setAdopting(true); setAdoptResult(""); setError("");
    try {
      const result = await dashboardRequest<{ checked: number; adopted: number; noMatch: number; errors: number }>("patch-group-tickets/adopt-untracked", { method: "POST" });
      setAdoptResult(`Checked ${result.checked} untracked ticket${result.checked === 1 ? "" : "s"} · adopted ${result.adopted} · ${result.noMatch} had no matching draft${result.errors ? ` · ${result.errors} failed` : ""}.`);
      setUntracked(null);
      await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not adopt untracked tickets."); }
    finally { setAdopting(false); }
  }

  // For an untracked ticket that's already closed with no fix verified (a
  // Combined/merged ticket closed before patching, for example), adoption
  // has nothing to reopen it into -- this writes it off instead and queues
  // its CVEs for a fresh ticket, skipping any CVE a different tracked
  // ticket already covers.
  // Replacing a CVE means a live CrowdStrike re-collection (up to a
  // 10-minute budget per tenant) -- reliably past this app's 20-second
  // request timeout the moment there's real work to do. This only starts
  // the pass and returns right away, same as validate-closures above.
  async function abandonUntrackedNow() {
    setAbandoning(true); setAbandonResult(""); setError("");
    try {
      const result = await dashboardRequest<{ started: boolean }>("patch-group-tickets/abandon-untracked", { method: "POST" });
      setAbandonResult(result.started
        ? "Started -- this can take several minutes if any CVEs need a fresh CrowdStrike collection. Click Refresh shortly to see results."
        : "Already running from a previous trigger -- that pass covers this too. Click Refresh shortly to see results.");
      setUntracked(null);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not start the abandon-and-replace pass."); }
    finally { setAbandoning(false); }
  }

  // Closes the confirmed 37 Combined children of #2655137 plus the parent
  // itself for real in ConnectWise (with a note explaining why), then
  // recuts every CVE they covered as a fresh, standalone ticket through the
  // normal consolidated-patch-plan pipeline -- since Combine/Merge
  // permissions in ConnectWise aren't changing and a merged ticket can't be
  // reliably separated through the API, this is the reset instead. Same
  // background-trigger pattern as the other slow actions above.
  async function closeAndRecutNow() {
    if (!window.confirm("Close all 38 tickets (the 37 Combined children and parent #2655137) in ConnectWise and recut their CVEs as new standalone tickets? This closes real, currently-tracked tickets -- continue?")) return;
    setRecutting(true); setRecutResult(""); setError("");
    try {
      const result = await dashboardRequest<{ started: boolean }>("patch-group-tickets/close-and-recut", { method: "POST" });
      setRecutResult(result.started
        ? "Started -- closing 38 tickets and recollecting CrowdStrike findings can take several minutes. Click Refresh shortly to see results."
        : "Already running from a previous trigger -- that pass covers this too. Click Refresh shortly to see results.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not start the close-and-recut pass."); }
    finally { setRecutting(false); }
  }

  // The trigger-and-return pattern above means a "Started" click gives no
  // eventual result -- this is the only way to tell a still-running pass
  // apart from one that failed silently, without guessing from whether
  // "Prepared" happened to go up yet.
  async function checkJobStatus(job: string, label: string) {
    setCheckingJob(job); setJobStatus(""); setError("");
    try {
      const result = await dashboardRequest<{ run: { status: "running" | "succeeded" | "failed"; result: unknown; error: string | null; startedAt: string; finishedAt: string | null } | null }>(`patch-group-tickets/job-status?job=${encodeURIComponent(job)}`);
      const run = result.run;
      if (!run) { setJobStatus(`${label}: never run yet.`); return; }
      const when = run.finishedAt ? new Date(run.finishedAt).toLocaleString() : `started ${new Date(run.startedAt).toLocaleString()}`;
      if (run.status === "running") setJobStatus(`${label}: still running (${when}).`);
      else if (run.status === "failed") setJobStatus(`${label}: failed at ${when} -- ${run.error}`);
      else setJobStatus(`${label}: finished ${when} -- ${JSON.stringify(run.result)}`);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not check job status."); }
    finally { setCheckingJob(""); }
  }

  const buckets = { "cut-open": 0, "cut-closed": 0, attention: 0, draft: 0 };
  let devicesCovered = 0;
  const distinctCves = new Set<string>();
  for (const r of rows) {
    buckets[stateBucket(r.row.state, r.row.ticketId, r.row.closed)]++;
    if (r.row.ticketId) devicesCovered += r.row.hostCount;
    for (const cve of r.cves) distinctCves.add(cve);
  }
  const cut = buckets["cut-open"] + buckets["cut-closed"];
  const overdueOpen = sla ? rows.filter(r => r.row.ticketId && !r.row.closed && ageDays(r.row.preparedAt) >= slaDaysFor(r.row.worstSeverity, sla)).length : 0;

  // Client-side, over what's already loaded -- a search/filter round trip
  // to the server for a table this size would just add latency for no
  // benefit. The stat tiles above double as filter toggles so the numbers
  // and the table stay in sync at a glance, not two disconnected views.
  const needle = search.trim().toLowerCase();
  const filteredRows = useMemo(() => rows.filter(r => {
    if (bucketFilter !== "all" && stateBucket(r.row.state, r.row.ticketId, r.row.closed) !== bucketFilter) return false;
    if (!needle) return true;
    const haystack = [r.scope, ...r.cves, r.row.ticketId?.toString(), r.row.company, r.row.companyName].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(needle);
  }), [rows, bucketFilter, needle]);

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5" aria-label="Patch ticket tracker">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-lg text-zinc-100">Patch ticket tracker</h2>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={styles.button} disabled={autoCreating} onClick={() => void runAutoCreateNow()}>{autoCreating ? "Running…" : "Run auto-create now"}</button>
        <button type="button" className={styles.button} disabled={validating} onClick={() => void runValidateClosuresNow()}>{validating ? "Validating…" : "Validate closures now"}</button>
        <button type="button" className={styles.button} disabled={findingUntracked} onClick={() => void findUntrackedNow()}>{findingUntracked ? "Checking…" : "Find untracked Atlas tickets"}</button>
        <button type="button" className={styles.button} disabled={adopting} onClick={() => void adoptUntrackedNow()}>{adopting ? "Adopting…" : "Adopt untracked tickets"}</button>
        <button type="button" className={styles.button} disabled={abandoning} onClick={() => void abandonUntrackedNow()}>{abandoning ? "Abandoning…" : "Abandon closed untracked + cut replacements"}</button>
        <button type="button" className={styles.button} disabled={recutting} onClick={() => void closeAndRecutNow()}>{recutting ? "Closing…" : "Close merged parent/children + recut as new"}</button>
        <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
      </div>
    </div>
    <p className={styles.resultNote}>Customer-linked consolidation plans prepared for review and their ConnectWise ticket status.</p>
    {autoCreateResult && <p role="status" className={`${styles.resultNote} mt-1`}>{autoCreateResult}</p>}
    {validateResult && <p role="status" className={`${styles.resultNote} mt-1`}>{validateResult} <button type="button" className="underline" disabled={!!checkingJob} onClick={() => void checkJobStatus("validate-closures", "Validate closures")}>{checkingJob === "validate-closures" ? "Checking…" : "Check status"}</button></p>}
    {adoptResult && <p role="status" className={`${styles.resultNote} mt-1`}>{adoptResult} Adopted tickets will be reopened on the next "Validate closures now" run.</p>}
    {abandonResult && <p role="status" className={`${styles.resultNote} mt-1`}>{abandonResult} New drafts appear below under "Awaiting review"; Critical/High ones are cut automatically by "Run auto-create now". <button type="button" className="underline" disabled={!!checkingJob} onClick={() => void checkJobStatus("abandon-and-replace", "Abandon + replace")}>{checkingJob === "abandon-and-replace" ? "Checking…" : "Check status"}</button></p>}
    {recutResult && <p role="status" className={`${styles.resultNote} mt-1`}>{recutResult} Closed tickets show "Closed in ConnectWise" above; new drafts appear below under "Awaiting review". <button type="button" className="underline" disabled={!!checkingJob} onClick={() => void checkJobStatus("close-and-recut", "Close + recut")}>{checkingJob === "close-and-recut" ? "Checking…" : "Check status"}</button></p>}
    {jobStatus && <p role="status" className={`${styles.resultNote} mt-1 font-medium`}>{jobStatus}</p>}
    {untracked && (untracked.length
      ? <div className="mt-2 rounded-lg border border-amber-800/60 bg-amber-950/10 p-3">
          <p className={styles.resultNote}>{untracked.length} Atlas ticket{untracked.length === 1 ? "" : "s"} in ConnectWise have no tracked row -- not created through this app, so no automation here can see or act on {untracked.length === 1 ? "it" : "them"} yet. Click "Adopt untracked tickets" to relink the ones whose original draft can still be matched. For any that are already closed with no fix behind them, "Abandon closed untracked + cut replacements" writes them off and queues their CVEs for a fresh ticket instead. Otherwise, handle these by hand:</p>
          <ul className="mt-2 space-y-1 text-sm">{untracked.map(t => <li key={t.id}>
            <a href={t.url} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{t.id}</a>
            {" — "}{t.status}{t.closed ? " (closed)" : ""}{t.summary ? ` — ${t.summary}` : ""}
          </li>)}</ul>
        </div>
      : <p role="status" className={`${styles.resultNote} mt-1`}>Every Atlas ticket in ConnectWise is tracked by this app.</p>)}
    <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
      <button type="button" aria-pressed={bucketFilter === "all"} onClick={() => setBucketFilter("all")}
        className={`rounded-xl border p-3 text-left transition-colors ${bucketFilter === "all" ? "border-zinc-500 bg-zinc-900" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700"}`}>
        <div className="text-2xl font-semibold text-white">{total}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Prepared</div></button>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{cut}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Tickets cut</div></div>
      <button type="button" aria-pressed={bucketFilter === "cut-open"} onClick={() => setBucketFilter(f => f === "cut-open" ? "all" : "cut-open")}
        className={`rounded-xl border p-3 text-left transition-colors ${bucketFilter === "cut-open" ? "border-emerald-500 bg-emerald-950/30" : "border-emerald-900/60 bg-emerald-950/10 hover:border-emerald-700"}`}>
        <div className="text-2xl font-semibold text-emerald-300">{buckets["cut-open"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Open in ConnectWise</div></button>
      <button type="button" aria-pressed={bucketFilter === "cut-closed"} onClick={() => setBucketFilter(f => f === "cut-closed" ? "all" : "cut-closed")}
        className={`rounded-xl border p-3 text-left transition-colors ${bucketFilter === "cut-closed" ? "border-zinc-500 bg-zinc-900" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700"}`}>
        <div className="text-2xl font-semibold text-zinc-300">{buckets["cut-closed"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Closed</div></button>
      <button type="button" aria-pressed={bucketFilter === "attention"} onClick={() => setBucketFilter(f => f === "attention" ? "all" : "attention")}
        className={`rounded-xl border p-3 text-left transition-colors ${bucketFilter === "attention" ? "border-[#ff8f96] bg-[rgba(179,14,20,0.16)]" : "border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] hover:border-[#ff8f96]/70"}`}>
        <div className="text-2xl font-semibold text-[#ff8f96]">{buckets.attention}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Needs attention</div></button>
    </div>
    <p className={`${styles.resultNote} mt-3`}>{devicesCovered.toLocaleString()} device-tickets covered by created tickets (a device can appear on more than one ticket) · {distinctCves.size.toLocaleString()} distinct CVEs referenced across tracked plans.{overdueOpen > 0 && <span className="ml-2 font-medium text-[#ff8f96]">· {overdueOpen} open ticket{overdueOpen === 1 ? "" : "s"} past its severity's SLA</span>}</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <div className="mt-4 flex flex-wrap items-center gap-2">
      <input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by CVE, ticket #, or company…"
        className="min-w-[16rem] flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-zinc-600 focus:outline-none" />
      {(bucketFilter !== "all" || search) && <button type="button" className={styles.button} onClick={() => { setBucketFilter("all"); setSearch(""); }}>Clear filters</button>}
      <span className="text-xs text-zinc-500">{filteredRows.length === rows.length ? `${rows.length} row${rows.length === 1 ? "" : "s"}` : `${filteredRows.length} of ${rows.length} rows`}</span>
    </div>
    <div className={`${styles.tableScroll} mt-3`}><table className={styles.table}>
      <thead><tr><th>Scope</th><th>Status</th><th>Company</th><th>Devices</th><th>Age</th><th>Prepared</th></tr></thead>
      <tbody>{filteredRows.map(r => <tr key={r.id}>
        <td title={`${r.row.remediationTitle || "Remediation"}\nResolves: ${r.cves.join(", ")}`}>{r.scope}</td>
        <td><StatusBadge bucket={stateBucket(r.row.state, r.row.ticketId, r.row.closed)} />
          <div className="mt-1">{r.row.ticketUrl && <a href={r.row.ticketUrl} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{r.row.ticketId}</a>}<span className="text-zinc-400"> {patchGroupTicketState(r.row)}</span></div>
          {r.row.createdBy === "auto-create" && <div className="mt-0.5 text-[11px] font-medium text-emerald-400">Auto-created (Critical/High)</div>}
          {r.row.slaEscalations > 0 && <div className="mt-0.5 text-[11px] font-medium text-[#ff8f96]">Auto-escalated ×{r.row.slaEscalations} (SLA breach)</div>}
          {r.row.error && <div className="mt-0.5 text-[11px] font-medium text-[#ff8f96]" title={r.row.error}>{r.row.error.length > 90 ? `${r.row.error.slice(0, 90)}…` : r.row.error}</div>}
          {r.row.mergedParentId && <div className="mt-0.5 text-[11px] font-medium text-amber-400">Merged into #{r.row.mergedParentId} in ConnectWise -- won't show as its own row on ConnectWise's board list, but is still tracked here</div>}</td>
        <td>{r.row.company ?? r.row.companyName ?? "Draft"}</td>
        <td>{r.row.hostCount.toLocaleString()}</td>
        <td>{trackerAgeBadge(r.row, sla ? slaDaysFor(r.row.worstSeverity, sla) : null)}</td>
        <td>{new Date(r.row.preparedAt).toLocaleString()}</td>
      </tr>)}</tbody>
    </table></div>
    {!rows.length && !loading && <p className={styles.resultNote}>No patch requests or consolidated plans prepared yet.</p>}
    {rows.length > 0 && !filteredRows.length && <p className={styles.resultNote}>No rows match this filter/search.</p>}
    {more && <p className={styles.resultNote}>The tracker reached its page limit; counts cover the loaded customer plans.</p>}
  </section>;
}
