"use client";
import { useEffect, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { patchTicketState, type PatchTicketSummary } from "@/lib/patch-ticket-types";
import PatchRequestPanel from "@/components/PatchRequestPanel";
import styles from "./QueryDashboard.module.css";

export default function PatchTicketRegister() {
  const [rows, setRows] = useState<PatchTicketSummary[]>([]), [more, setMore] = useState(false), [error, setError] = useState(""), [loading, setLoading] = useState(false);
  const [cve, setCve] = useState<string | null>(null); const dialog = useRef<HTMLDialogElement>(null);
  async function reload() {
    setLoading(true); setError("");
    try { const data = await dashboardRequest<{ requests: PatchTicketSummary[]; more: boolean }>("patch-tickets"); setRows(data.requests); setMore(data.more); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not load patch requests."); } finally { setLoading(false); }
  }
  useEffect(() => { void reload(); }, []);
  useEffect(() => { if (cve) dialog.current?.showModal(); }, [cve]);
  return <section className="rounded-xl border border-zinc-800 bg-zinc-950 p-5" aria-label="Patch ticket register">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2"><h2 className="text-lg text-zinc-100">Patch requests and tickets</h2><button type="button" className={styles.button} disabled={loading} onClick={reload}>{loading ? "Loading…" : "Refresh requests"}</button></div>
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    <div className={styles.tableScroll}><table className={styles.table}><thead><tr><th>CVE</th><th>Ticket / state</th><th>Company</th><th>Devices</th><th>Prepared</th></tr></thead><tbody>
      {rows.map(row => <tr key={row.id}><td><button type="button" className={styles.cveButton} onClick={() => setCve(row.cve)}>{row.cve}</button></td><td>{row.ticketUrl && <a href={row.ticketUrl} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">#{row.ticketId}</a>}<div>{patchTicketState(row)}</div></td><td>{row.company ?? "Draft"}</td><td>{row.hostCount.toLocaleString()}</td><td>{new Date(row.preparedAt).toLocaleString()}</td></tr>)}
    </tbody></table></div>
    {!rows.length && !loading && <p className={styles.resultNote}>No saved requests yet. Click any CVE and prepare a patch request to begin.</p>}
    {more && <p className={styles.resultNote}>Showing the latest 100 requests. Open a CVE for its own request history.</p>}
    <dialog ref={dialog} className={styles.detail} aria-label="CVE patch requests" onClose={() => { setCve(null); void reload(); }} onClick={e => { if (e.target === e.currentTarget) dialog.current?.close(); }}><div className={styles.detailBody}>
      <div className={styles.detailTop}><h2>{cve}</h2><button type="button" className={styles.button} onClick={() => dialog.current?.close()}>Close</button></div>
      {cve && <PatchRequestPanel key={cve} cve={cve} />}
    </div></dialog>
  </section>;
}
