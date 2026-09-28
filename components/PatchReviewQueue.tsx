"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { PatchGroup } from "@/lib/patch-request";
import { patchReviewRows } from "@/lib/patch-review-rows";
import { patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import ConnectWiseGroupTicket from "@/components/ConnectWiseGroupTicket";
import styles from "./QueryDashboard.module.css";

type Detail = { request: PatchGroupTicketSummary; group: PatchGroup };
type Page = { requests: PatchGroupTicketSummary[]; more: boolean; total: number; pending: number; approved: number };

export default function PatchReviewQueue({ companyId }: { companyId: string }) {
  const [rows, setRows] = useState<PatchGroupTicketSummary[]>([]);
  const [selected, setSelected] = useState<Detail | null>(null);
  const [page, setPage] = useState(1);
  const [more, setMore] = useState(false);
  const [counts, setCounts] = useState({ total: 0, pending: 0, approved: 0 });
  const [detailPage, setDetailPage] = useState(1);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(async (nextPage = 1) => {
    setBusy("load"); setError("");
    try {
      const data = await dashboardRequest<Page>(`patch-group-tickets?review=1&page=${nextPage}&companyId=${encodeURIComponent(companyId)}`);
      setRows(current => nextPage === 1 ? data.requests : [...current, ...data.requests]);
      setPage(nextPage); setMore(data.more);
      setCounts({ total: data.total, pending: data.pending, approved: data.approved });
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not load the review queue."); }
    finally { setBusy(""); }
  }, [companyId]);
  useEffect(() => {
    void load();
    const timer = setInterval(() => { void load(); }, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  async function open(id: string) {
    setBusy(id); setError("");
    try { setSelected(await dashboardRequest<Detail>(`patch-group-tickets/${id}?packet=1`)); setDetailPage(1); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not open this draft."); }
    finally { setBusy(""); }
  }
  async function review(action: "approve" | "dismiss" | "reopen") {
    if (!selected) return;
    setBusy(action); setError("");
    try {
      const data = await dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${selected.request.id}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }),
      });
      setSelected({ ...selected, request: data.request });
      setRows(current => current.map(row => row.id === data.request.id ? data.request : row));
      await load();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save the review decision."); }
    finally { setBusy(""); }
  }
  function download(group: PatchGroup) {
    const url = URL.createObjectURL(new Blob([group.csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = `${group.label}-patch-request.csv`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const detailRows = useMemo(() => selected ? patchReviewRows(selected.group) : [], [selected]);
  return <section aria-label="Consolidation review queue" className="rounded-2xl border border-zinc-800 bg-[#080808] p-5 sm:p-7">
    <div className="flex flex-wrap items-start justify-between gap-3"><div>
      <p className="text-xs uppercase tracking-[0.25em] text-red-500">Consolidation</p>
      <h2 className="mt-2 text-xl font-semibold text-white">Review queue</h2>
      <p className="mt-2 max-w-2xl text-sm text-zinc-400">Awaiting review is ranked by devices affected — the biggest-impact remediation for this customer sits at the top. Approving the next one prepares its ticket; sending still requires the ConnectWise form.</p>
    </div><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void load()}>Refresh</button></div>
    <p className="mt-4 text-sm text-zinc-400">{counts.pending} awaiting review · {counts.approved} approved · {rows.length} of {counts.total} loaded</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {!rows.length && !busy && <p className="mt-5 text-sm text-zinc-400">No saved consolidation candidates yet.</p>}
    <div className={`${styles.tableScroll} mt-4`}><table className={styles.table}>
      <thead><tr><th>Customer / source</th><th>Remediation</th><th>CVEs</th><th>Assets</th><th>Findings</th><th>State</th><th>Prepared</th><th>Details</th></tr></thead>
      <tbody>{rows.map(row => {
        const isNext = row.id === rows.find(r => r.reviewState === "pending")?.id;
        return <tr key={row.id}>
        <td>{row.source === "stored-findings" ? row.companyName : `CrowdStrike tenant ${row.tenantId}`}</td>
        <td>{isNext && <span className="mr-2 rounded-full border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.12)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[#ff8f96]">Next</span>}{row.remediationTitle || "Recommended remediation"}</td>
        <td>{row.cves.join(", ")}</td><td>{row.hostCount.toLocaleString()}</td><td>{row.findingCount.toLocaleString()}</td>
        <td>{patchGroupTicketState(row)}</td><td>{new Date(row.preparedAt).toLocaleString()}</td>
        <td><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void open(row.id)}>{busy === row.id ? "Opening…" : "Review"}</button></td>
      </tr>;
      })}</tbody>
    </table></div>
    {more && <button type="button" className={`${styles.button} mt-4`} disabled={Boolean(busy)} onClick={() => void load(page + 1)}>Load more</button>}
    {selected && <div className="mt-6 rounded-xl border border-zinc-700 bg-zinc-950 p-5">
      <div className="flex flex-wrap justify-between gap-3"><div><h3 className="text-lg font-medium text-white">{selected.group.title || "Recommended remediation"}</h3>
        <p className="mt-1 text-sm text-zinc-400">{selected.group.deviceCount.toLocaleString()} assets · {selected.group.findingCount.toLocaleString()} findings · {selected.group.source === "stored-findings" ? `${selected.group.companyName} · ${selected.group.connectors?.join(", ")}` : `CrowdStrike tenant ${selected.group.tenantId}`}</p></div>
        <button type="button" className={styles.button} onClick={() => setSelected(null)}>Close</button></div>
      <p className="mt-4 whitespace-pre-wrap text-sm text-zinc-200">{selected.group.action || "No remediation action was supplied by the source."}</p>
      <p className="mt-3 text-xs text-zinc-400">Resolves {selected.group.cves.join(", ")}</p>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3"><h4 className="font-medium text-white">Affected findings</h4>
        <button type="button" className={styles.button} onClick={() => download(selected.group)}>Download full findings list</button></div>
      <p className="mt-2 text-xs text-zinc-400">{detailRows.length.toLocaleString()} asset and CVE rows in this review packet. The download contains the complete source detail.</p>
      <div className={`${styles.tableScroll} mt-3`}><table className={styles.table}>
        <thead><tr><th>Asset</th><th>CVE</th><th>Severity</th><th>Risk</th><th>Source</th><th>Host / IP</th><th>OS</th><th>Exposure</th><th>Finding ID</th></tr></thead>
        <tbody>{detailRows.slice((detailPage - 1) * 50, detailPage * 50).map((row, index) => <tr key={`${row.asset}-${row.cve}-${index}`}>
          <td>{row.asset}</td><td>{row.cve}</td><td>{row.severity || "—"}</td>
          <td>{typeof row.risk === "number" && row.risk >= 0 ? row.risk : "—"}</td>
          <td>{row.connectors?.join(", ") || "—"}</td>
          <td>{row.ip || row.hostname || "—"}</td><td>{row.os || "—"}</td>
          <td>{row.exposure || "—"}</td><td>{row.findingId || "—"}</td>
        </tr>)}</tbody>
      </table></div>
      {detailRows.length > 50 && <div className="mt-3 flex items-center gap-3 text-sm text-zinc-400">
        <button type="button" className={styles.button} disabled={detailPage === 1} onClick={() => setDetailPage(page => page - 1)}>Previous</button>
        <span>Page {detailPage} of {Math.ceil(detailRows.length / 50)}</span>
        <button type="button" className={styles.button} disabled={detailPage * 50 >= detailRows.length} onClick={() => setDetailPage(page => page + 1)}>Next</button>
      </div>}
      <div className="mt-5 flex flex-wrap gap-2">
        {selected.request.reviewState === "pending" && <><button type="button" className={styles.primaryButton} disabled={Boolean(busy)} onClick={() => void review("approve")}>Approve for ticket</button>
          <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void review("dismiss")}>Dismiss</button></>}
        {selected.request.reviewState === "dismissed" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void review("reopen")}>Reopen for review</button>}
      </div>
      {selected.request.reviewState === "approved" && <ConnectWiseGroupTicket key={`${selected.request.id}-approved`} group={selected.group} requestId={selected.request.id} />}
    </div>}
  </section>;
}
