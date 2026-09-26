"use client";
import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { patchTicketState, type PatchTicketSummary } from "@/lib/patch-ticket-types";
import { patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import styles from "./QueryDashboard.module.css";

type Row =
  | { kind: "cve"; id: string; scope: string; cves: string[]; row: PatchTicketSummary }
  | { kind: "group"; id: string; scope: string; cves: string[]; row: PatchGroupTicketSummary };

function stateBucket(state: string, ticketId: number | null, closed: boolean): "cut-open" | "cut-closed" | "attention" | "draft" {
  if (ticketId) return closed ? "cut-closed" : "cut-open";
  if (state === "failed" || state === "uncertain") return "attention";
  return "draft";
}

export default function PatchTicketTracker() {
  const [rows, setRows] = useState<Row[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [cveData, groupData] = await Promise.all([
        dashboardRequest<{ requests: PatchTicketSummary[]; more: boolean }>("patch-tickets"),
        dashboardRequest<{ requests: PatchGroupTicketSummary[]; more: boolean }>("patch-group-tickets"),
      ]);
      const combined: Row[] = [
        ...cveData.requests.map((row): Row => ({ kind: "cve", id: row.id, scope: row.cve, cves: [row.cve], row })),
        ...groupData.requests.map((row): Row => ({ kind: "group", id: row.id,
          scope: row.cves.length === 1 ? row.cves[0] : `${(row.remediationTitle || "Remediation").slice(0, 48)} · ${row.cves.length} CVEs`, cves: row.cves, row })),
      ].sort((a, b) => new Date(b.row.preparedAt).getTime() - new Date(a.row.preparedAt).getTime());
      setRows(combined); setMore(cveData.more || groupData.more);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load the ticket tracker."); }
    finally { setLoading(false); }
  }, []);
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

  return <section className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-5" aria-label="Patch ticket tracker">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 className="text-lg text-zinc-100">Patch ticket tracker</h2>
      <button type="button" className={styles.button} disabled={loading} onClick={() => void reload()}>{loading ? "Loading…" : "Refresh"}</button>
    </div>
    <p className={styles.resultNote}>Every patch request and consolidated patch plan that has been prepared, whether or not it became a ConnectWise ticket — single-CVE and multi-CVE tickets together.</p>
    <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{rows.length}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Prepared</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-white">{cut}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Tickets cut</div></div>
      <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/10 p-3"><div className="text-2xl font-semibold text-emerald-300">{buckets["cut-open"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Open in ConnectWise</div></div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3"><div className="text-2xl font-semibold text-zinc-300">{buckets["cut-closed"]}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Closed</div></div>
      <div className="rounded-xl border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.08)] p-3"><div className="text-2xl font-semibold text-[#ff8f96]">{buckets.attention}</div><div className="text-[11px] uppercase tracking-[0.14em] text-zinc-500">Needs attention</div></div>
    </div>
    <p className={`${styles.resultNote} mt-3`}>{devicesCovered.toLocaleString()} device-tickets covered by created tickets (a device can appear on more than one ticket) · {distinctCves.size.toLocaleString()} distinct CVEs referenced across every tracked ticket.</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <div className={`${styles.tableScroll} mt-4`}><table className={styles.table}>
      <thead><tr><th>Type</th><th>Scope</th><th>Ticket / state</th><th>Company</th><th>Devices</th><th>Prepared</th></tr></thead>
      <tbody>{rows.map(r => <tr key={`${r.kind}-${r.id}`}>
        <td>{r.kind === "cve" ? "Single CVE" : "Consolidated"}</td>
        <td title={r.kind === "group" ? `${r.row.remediationTitle || "Remediation"}\nResolves: ${r.cves.join(", ")}` : r.scope}>{r.scope}</td>
        <td>{r.row.ticketUrl && <a href={r.row.ticketUrl} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{r.row.ticketId}</a>}<div>{r.kind === "cve" ? patchTicketState(r.row) : patchGroupTicketState(r.row)}</div></td>
        <td>{r.row.company ?? "Draft"}</td>
        <td>{r.row.hostCount.toLocaleString()}</td>
        <td>{new Date(r.row.preparedAt).toLocaleString()}</td>
      </tr>)}</tbody>
    </table></div>
    {!rows.length && !loading && <p className={styles.resultNote}>No patch requests or consolidated plans prepared yet.</p>}
    {more && <p className={styles.resultNote}>Showing the latest 100 of each type.</p>}
  </section>;
}
