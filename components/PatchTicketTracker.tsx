"use client";
import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { ageDays, patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import styles from "./QueryDashboard.module.css";

type Row = { id: string; scope: string; cves: string[]; row: PatchGroupTicketSummary };

function stateBucket(state: string, ticketId: number | null, closed: boolean): "cut-open" | "cut-closed" | "attention" | "draft" {
  if (ticketId) return closed ? "cut-closed" : "cut-open";
  if (state === "failed" || state === "uncertain") return "attention";
  return "draft";
}
function trackerAgeBadge(row: PatchGroupTicketSummary) {
  const days = ageDays(row.preparedAt);
  const openTicket = Boolean(row.ticketId) && !row.closed;
  if (!openTicket) return <span className="text-zinc-500">{days}d</span>;
  const cls = days >= 14 ? "font-semibold text-[#ff8f96]" : days >= 5 ? "text-amber-400" : "text-zinc-400";
  return <span className={cls}>{days}d{days >= 14 ? " · overdue" : ""}</span>;
}

export default function PatchTicketTracker({ companyId }: { companyId: string }) {
  const [rows, setRows] = useState<Row[]>([]);
  const [more, setMore] = useState(false);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

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

  const buckets = { "cut-open": 0, "cut-closed": 0, attention: 0, draft: 0 };
  let devicesCovered = 0;
  const distinctCves = new Set<string>();
  for (const r of rows) {
    buckets[stateBucket(r.row.state, r.row.ticketId, r.row.closed)]++;
    if (r.row.ticketId) devicesCovered += r.row.hostCount;
    for (const cve of r.cves) distinctCves.add(cve);
  }
  const cut = buckets["cut-open"] + buckets["cut-closed"];
  const overdueOpen = rows.filter(r => r.row.ticketId && !r.row.closed && ageDays(r.row.preparedAt) >= 14).length;

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5" aria-label="Patch ticket tracker">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-lg text-zinc-100">Patch ticket tracker</h2>
      <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
    </div>
    <p className={styles.resultNote}>Customer-linked consolidation plans prepared for review and their ConnectWise ticket status.</p>
    <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{total}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Prepared</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{cut}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Tickets cut</div></div>
      <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/10 p-3"><div className="text-2xl font-semibold text-emerald-300">{buckets["cut-open"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Open in ConnectWise</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-zinc-300">{buckets["cut-closed"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Closed</div></div>
      <div className="rounded-xl border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] p-3"><div className="text-2xl font-semibold text-[#ff8f96]">{buckets.attention}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Needs attention</div></div>
    </div>
    <p className={`${styles.resultNote} mt-3`}>{devicesCovered.toLocaleString()} device-tickets covered by created tickets (a device can appear on more than one ticket) · {distinctCves.size.toLocaleString()} distinct CVEs referenced across tracked plans.{overdueOpen > 0 && <span className="ml-2 font-medium text-[#ff8f96]">· {overdueOpen} open ticket{overdueOpen === 1 ? "" : "s"} overdue 14+ days</span>}</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <div className={`${styles.tableScroll} mt-4`}><table className={styles.table}>
      <thead><tr><th>Type</th><th>Scope</th><th>Ticket / state</th><th>Company</th><th>Devices</th><th>Age</th><th>Prepared</th></tr></thead>
      <tbody>{rows.map(r => <tr key={r.id}>
        <td>Customer remediation</td>
        <td title={`${r.row.remediationTitle || "Remediation"}\nResolves: ${r.cves.join(", ")}`}>{r.scope}</td>
        <td>{r.row.ticketUrl && <a href={r.row.ticketUrl} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{r.row.ticketId}</a>}<div>{patchGroupTicketState(r.row)}</div></td>
        <td>{r.row.company ?? r.row.companyName ?? "Draft"}</td>
        <td>{r.row.hostCount.toLocaleString()}</td>
        <td>{trackerAgeBadge(r.row)}</td>
        <td>{new Date(r.row.preparedAt).toLocaleString()}</td>
      </tr>)}</tbody>
    </table></div>
    {!rows.length && !loading && <p className={styles.resultNote}>No patch requests or consolidated plans prepared yet.</p>}
    {more && <p className={styles.resultNote}>The tracker reached its page limit; counts cover the loaded customer plans.</p>}
  </section>;
}
