"use client";
import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { ageDays, patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import { slaDaysFor } from "@/lib/vuln-sla";
import type { SlaSettings } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

type Row = { id: string; scope: string; cves: string[]; row: PatchGroupTicketSummary };

function stateBucket(state: string, ticketId: number | null, closed: boolean): "cut-open" | "cut-closed" | "attention" | "draft" {
  if (ticketId) return closed ? "cut-closed" : "cut-open";
  if (state === "failed" || state === "uncertain") return "attention";
  return "draft";
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
      const result = await dashboardRequest<{ checked: number; created: number; errors: number; priorityBackfill: { checked: number; updated: number; errors: number } }>("patch-group-tickets/auto-create", { method: "POST" });
      const p = result.priorityBackfill;
      const priorityNote = p.checked ? ` Priority backfill: updated ${p.updated} of ${p.checked} existing ticket${p.checked === 1 ? "" : "s"}${p.errors ? ` · ${p.errors} failed` : ""}.` : "";
      setAutoCreateResult(`Checked ${result.checked} eligible draft${result.checked === 1 ? "" : "s"} · created ${result.created}${result.errors ? ` · ${result.errors} failed` : ""}.${priorityNote}`);
      await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not run auto-create."); }
    finally { setAutoCreating(false); }
  }

  async function runValidateClosuresNow() {
    setValidating(true); setValidateResult(""); setError("");
    try {
      const result = await dashboardRequest<{ checked: number; reopened: number; confirmedFixed: number; needsManualUnmerge: number; errors: number }>("patch-group-tickets/validate-closures", { method: "POST" });
      const unmergeNote = result.needsManualUnmerge ? ` · ${result.needsManualUnmerge} merged into a parent ticket and need manual separation in ConnectWise first` : "";
      setValidateResult(`Checked ${result.checked} closed ticket${result.checked === 1 ? "" : "s"} · reopened ${result.reopened} unverified · confirmed ${result.confirmedFixed} fixed${unmergeNote}${result.errors ? ` · ${result.errors} failed` : ""}.`);
      await reload();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not run closure validation."); }
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

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5" aria-label="Patch ticket tracker">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-lg text-zinc-100">Patch ticket tracker</h2>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={styles.button} disabled={autoCreating} onClick={() => void runAutoCreateNow()}>{autoCreating ? "Running…" : "Run auto-create now"}</button>
        <button type="button" className={styles.button} disabled={validating} onClick={() => void runValidateClosuresNow()}>{validating ? "Validating…" : "Validate closures now"}</button>
        <button type="button" className={styles.button} disabled={findingUntracked} onClick={() => void findUntrackedNow()}>{findingUntracked ? "Checking…" : "Find untracked Atlas tickets"}</button>
        <button type="button" className={styles.button} disabled={adopting} onClick={() => void adoptUntrackedNow()}>{adopting ? "Adopting…" : "Adopt untracked tickets"}</button>
        <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
      </div>
    </div>
    <p className={styles.resultNote}>Customer-linked consolidation plans prepared for review and their ConnectWise ticket status.</p>
    {autoCreateResult && <p role="status" className={`${styles.resultNote} mt-1`}>{autoCreateResult}</p>}
    {validateResult && <p role="status" className={`${styles.resultNote} mt-1`}>{validateResult}</p>}
    {adoptResult && <p role="status" className={`${styles.resultNote} mt-1`}>{adoptResult} Adopted tickets will be reopened on the next "Validate closures now" run.</p>}
    {untracked && (untracked.length
      ? <div className="mt-2 rounded-lg border border-amber-800/60 bg-amber-950/10 p-3">
          <p className={styles.resultNote}>{untracked.length} Atlas ticket{untracked.length === 1 ? "" : "s"} in ConnectWise have no tracked row -- not created through this app, so no automation here can see or act on {untracked.length === 1 ? "it" : "them"} yet. Click "Adopt untracked tickets" to relink the ones whose original draft can still be matched, or handle these by hand:</p>
          <ul className="mt-2 space-y-1 text-sm">{untracked.map(t => <li key={t.id}>
            <a href={t.url} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{t.id}</a>
            {" — "}{t.status}{t.closed ? " (closed)" : ""}{t.summary ? ` — ${t.summary}` : ""}
          </li>)}</ul>
        </div>
      : <p role="status" className={`${styles.resultNote} mt-1`}>Every Atlas ticket in ConnectWise is tracked by this app.</p>)}
    <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{total}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Prepared</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{cut}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Tickets cut</div></div>
      <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/10 p-3"><div className="text-2xl font-semibold text-emerald-300">{buckets["cut-open"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Open in ConnectWise</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-zinc-300">{buckets["cut-closed"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Closed</div></div>
      <div className="rounded-xl border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] p-3"><div className="text-2xl font-semibold text-[#ff8f96]">{buckets.attention}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Needs attention</div></div>
    </div>
    <p className={`${styles.resultNote} mt-3`}>{devicesCovered.toLocaleString()} device-tickets covered by created tickets (a device can appear on more than one ticket) · {distinctCves.size.toLocaleString()} distinct CVEs referenced across tracked plans.{overdueOpen > 0 && <span className="ml-2 font-medium text-[#ff8f96]">· {overdueOpen} open ticket{overdueOpen === 1 ? "" : "s"} past its severity's SLA</span>}</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <div className={`${styles.tableScroll} mt-4`}><table className={styles.table}>
      <thead><tr><th>Type</th><th>Scope</th><th>Ticket / state</th><th>Company</th><th>Devices</th><th>Age</th><th>Prepared</th></tr></thead>
      <tbody>{rows.map(r => <tr key={r.id}>
        <td>Customer remediation</td>
        <td title={`${r.row.remediationTitle || "Remediation"}\nResolves: ${r.cves.join(", ")}`}>{r.scope}</td>
        <td>{r.row.ticketUrl && <a href={r.row.ticketUrl} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{r.row.ticketId}</a>}<div>{patchGroupTicketState(r.row)}</div>
          {r.row.createdBy === "auto-create" && <div className="mt-0.5 text-[11px] font-medium text-emerald-400">Auto-created (Critical/High)</div>}
          {r.row.slaEscalations > 0 && <div className="mt-0.5 text-[11px] font-medium text-[#ff8f96]">Auto-escalated ×{r.row.slaEscalations} (SLA breach)</div>}</td>
        <td>{r.row.company ?? r.row.companyName ?? "Draft"}</td>
        <td>{r.row.hostCount.toLocaleString()}</td>
        <td>{trackerAgeBadge(r.row, sla ? slaDaysFor(r.row.worstSeverity, sla) : null)}</td>
        <td>{new Date(r.row.preparedAt).toLocaleString()}</td>
      </tr>)}</tbody>
    </table></div>
    {!rows.length && !loading && <p className={styles.resultNote}>No patch requests or consolidated plans prepared yet.</p>}
    {more && <p className={styles.resultNote}>The tracker reached its page limit; counts cover the loaded customer plans.</p>}
  </section>;
}
