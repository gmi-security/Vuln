"use client";

import { useCallback, useEffect, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { PatchGroup } from "@/lib/patch-request";
import { patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import ConnectWiseGroupTicket from "@/components/ConnectWiseGroupTicket";
import styles from "./QueryDashboard.module.css";

type Detail = { request: PatchGroupTicketSummary; group: PatchGroup };
type Page = { requests: PatchGroupTicketSummary[]; more: boolean };

export default function PatchReviewQueue() {
  const [rows, setRows] = useState<PatchGroupTicketSummary[]>([]);
  const [selected, setSelected] = useState<Detail | null>(null);
  const [page, setPage] = useState(1);
  const [more, setMore] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(async (nextPage = 1) => {
    setBusy("load"); setError("");
    try {
      const data = await dashboardRequest<Page>(`patch-group-tickets?review=1&page=${nextPage}`);
      setRows(current => nextPage === 1 ? data.requests : [...current, ...data.requests]);
      setPage(nextPage); setMore(data.more);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not load the review queue."); }
    finally { setBusy(""); }
  }, []);
  useEffect(() => {
    void load();
    const timer = setInterval(() => { void load(); }, 60_000);
    return () => clearInterval(timer);
  }, [load]);

  async function open(id: string) {
    setBusy(id); setError("");
    try { setSelected(await dashboardRequest<Detail>(`patch-group-tickets/${id}?packet=1`)); }
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
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save the review decision."); }
    finally { setBusy(""); }
  }
  function download(group: PatchGroup) {
    const url = URL.createObjectURL(new Blob([group.csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = `${group.label}-patch-request.csv`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const pending = rows.filter(row => row.reviewState === "pending").length;
  const approved = rows.filter(row => row.reviewState === "approved").length;
  return <section aria-label="Consolidation review queue" className="rounded-2xl border border-zinc-800 bg-[#080808] p-5 sm:p-7">
    <div className="flex flex-wrap items-start justify-between gap-3"><div>
      <p className="text-xs uppercase tracking-[0.25em] text-red-500">Consolidation</p>
      <h2 className="mt-2 text-xl font-semibold text-white">Review queue</h2>
      <p className="mt-2 max-w-2xl text-sm text-zinc-400">Saved patch candidates wait here for an analyst. Approval prepares a ticket; sending still requires the ConnectWise form.</p>
    </div><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void load()}>Refresh</button></div>
    <p className="mt-4 text-sm text-zinc-400">{pending} awaiting review · {approved} approved · {rows.length} loaded</p>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {!rows.length && !busy && <p className="mt-5 text-sm text-zinc-400">No saved consolidation candidates yet.</p>}
    <div className="mt-4 divide-y divide-zinc-800 border-y border-zinc-800">{rows.map(row => <div key={row.id} className="flex flex-wrap items-center justify-between gap-3 py-4">
      <div className="min-w-0"><p className="font-medium text-zinc-100">{row.remediationTitle || "Recommended remediation"}</p>
        <p className="mt-1 text-xs text-zinc-400">{row.cves.length} CVE{row.cves.length === 1 ? "" : "s"} · {row.hostCount.toLocaleString()} affected assets · {row.source === "stored-findings" ? row.companyName : `CrowdStrike tenant ${row.tenantId}`}</p>
        <p className="mt-1 text-xs text-zinc-500">{patchGroupTicketState(row)} · {new Date(row.preparedAt).toLocaleString()}</p></div>
      <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void open(row.id)}>{busy === row.id ? "Opening…" : "Review"}</button>
    </div>)}</div>
    {more && <button type="button" className={`${styles.button} mt-4`} disabled={Boolean(busy)} onClick={() => void load(page + 1)}>Load more</button>}
    {selected && <div className="mt-6 rounded-xl border border-zinc-700 bg-zinc-950 p-5">
      <div className="flex flex-wrap justify-between gap-3"><div><h3 className="text-lg font-medium text-white">{selected.group.title || "Recommended remediation"}</h3>
        <p className="mt-1 text-sm text-zinc-400">{selected.group.deviceCount.toLocaleString()} assets · {selected.group.findingCount.toLocaleString()} findings · {selected.group.source === "stored-findings" ? `${selected.group.companyName} · ${selected.group.connectors?.join(", ")}` : `CrowdStrike tenant ${selected.group.tenantId}`}</p></div>
        <button type="button" className={styles.button} onClick={() => setSelected(null)}>Close</button></div>
      <p className="mt-4 whitespace-pre-wrap text-sm text-zinc-200">{selected.group.action || "No remediation action was supplied by the source."}</p>
      <p className="mt-3 text-xs text-zinc-400">Resolves {selected.group.cves.join(", ")}</p>
      <button type="button" className={`${styles.button} mt-4`} onClick={() => download(selected.group)}>Download affected devices</button>
      <div className="mt-5 flex flex-wrap gap-2">
        {selected.request.reviewState === "pending" && <><button type="button" className={styles.primaryButton} disabled={Boolean(busy)} onClick={() => void review("approve")}>Approve for ticket</button>
          <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void review("dismiss")}>Dismiss</button></>}
        {selected.request.reviewState === "dismissed" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => void review("reopen")}>Reopen for review</button>}
      </div>
      {selected.request.reviewState === "approved" && <ConnectWiseGroupTicket key={`${selected.request.id}-approved`} group={selected.group} requestId={selected.request.id} />}
    </div>}
  </section>;
}
