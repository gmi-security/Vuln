"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { automatedTicketBody, patchTicketState, type PatchTicketDetail, type PatchTicketSummary } from "@/lib/patch-ticket-types";
import type { PatchRequest } from "@/lib/patch-request";
import type { CWDefaults } from "@/lib/connectwise-client";
import { ConnectWiseRouting, ConnectWiseSelect, type CWSettings } from "@/components/ConnectWiseFields";
import styles from "./QueryDashboard.module.css";

export default function ConnectWisePatchTicket({ cve, packet, requestId, onResume }: {
  cve: string; packet: PatchRequest | null; requestId?: string; onResume: (detail: PatchTicketDetail) => void;
}) {
  const [settings, setSettings] = useState<CWSettings | null>(null), [requests, setRequests] = useState<PatchTicketSummary[]>([]);
  const [current, setCurrent] = useState<PatchTicketSummary | null>(null), [review, setReview] = useState(false);
  const [routing, setRouting] = useState<CWDefaults>({}), [companyId, setCompanyId] = useState<number>();
  const [title, setTitle] = useState(""), [body, setBody] = useState(""), [busy, setBusy] = useState("");
  const [error, setError] = useState(""), [message, setMessage] = useState("");
  const generation = useRef(0);
  const reload = useCallback(async () => {
    const data = await dashboardRequest<{ requests: PatchTicketSummary[] }>(`patch-tickets?cve=${encodeURIComponent(cve)}`);
    setRequests(data.requests);
    return data.requests;
  }, [cve]);
  useEffect(() => {
    let live = true;
    Promise.all([dashboardRequest<CWSettings>("connectwise"), dashboardRequest<{ requests: PatchTicketSummary[] }>(`patch-tickets?cve=${encodeURIComponent(cve)}`)])
      .then(([config, data]) => { if (live) { setSettings(config); setRouting(config.defaults); setRequests(data.requests); } })
      .catch(e => { if (live) setError(e.message); });
    return () => { live = false; generation.current++; };
  }, [cve]);
  useEffect(() => {
    let live = true; setReview(false); setCompanyId(undefined); setCurrent(null); setMessage("");
    if (packet) { setTitle(`Patch ${packet.cve} | ${packet.hostCount} affected devices`.slice(0, 100)); setBody(automatedTicketBody(packet)); }
    if (requestId) dashboardRequest<{ request: PatchTicketSummary }>(`patch-tickets/${requestId}`).then(data => { if (live) { setCurrent(data.request); void reload().catch(() => {}); } }).catch(e => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [requestId, packet, reload]);
  async function track(id: string, token: number) {
    for (let attempt = 0; attempt < 95; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      if (generation.current !== token) return;
      const data = await dashboardRequest<{ request: PatchTicketSummary }>(`patch-tickets/${id}`);
      if (generation.current !== token) return;
      setCurrent(data.request);
      if (data.request.state !== "creating" && data.request.attachmentState !== "uploading" && !(attempt < 2 && data.request.state === "created" && data.request.attachmentState === "pending" && !data.request.error)) { await reload(); return; }
    }
    setMessage("The operation is still pending. Its saved request can be checked again below.");
  }
  async function action(id: string, operation: string, extra: Record<string, unknown> = {}) {
    const token = ++generation.current; setBusy(operation); setError(""); setMessage("");
    try {
      const data = await dashboardRequest<{ request: PatchTicketSummary }>(`patch-tickets/${id}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: operation, ...extra }) });
      if (generation.current !== token) return;
      setCurrent(data.request); setReview(false);
      if (operation === "create" || operation === "retry-attachment") await track(id, token); else await reload();
    } catch (e) { if (generation.current === token) { setError(e instanceof Error ? e.message : "Could not process this request."); void reload().catch(() => {}); } }
    finally { if (generation.current === token) setBusy(""); }
  }
  async function verifyFix() {
    if (!current) return;
    const token = ++generation.current; setBusy("verify-fix"); setError(""); setMessage("Checking CrowdStrike for this CVE's current status. This can take a minute or two.");
    try {
      let job = await dashboardRequest<{ jobId: string; status: string; error?: string; ticket?: { request: PatchTicketSummary } }>("verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ticketKind: "cve", ticketId: current.id }) });
      const deadline = Date.now() + 5 * 60_000;
      while (["queued", "running"].includes(job.status)) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        if (generation.current !== token) return;
        if (Date.now() >= deadline) throw new Error("The verification job expired. Please try again.");
        job = await dashboardRequest(`jobs/${job.jobId}`);
      }
      if (generation.current !== token) return;
      if (job.status !== "succeeded" || !job.ticket) throw new Error(job.error || "Verification failed. Please retry.");
      setCurrent(job.ticket.request); setMessage("Verification complete."); await reload();
    } catch (e) { if (generation.current === token) { setError(e instanceof Error ? e.message : "Verification failed. Please retry."); setMessage(""); } }
    finally { if (generation.current === token) setBusy(""); }
  }
  async function resume(id: string) {
    setBusy("resume"); setError("");
    try { onResume(await dashboardRequest<PatchTicketDetail>(`patch-tickets/${id}?packet=1`)); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not open this saved request."); } finally { setBusy(""); }
  }
  const canCreate = settings?.configured && packet && requestId && packet.tenantIds?.length === 1 && (!current || ["prepared", "failed"].includes(current.state));
  return <section className={styles.patchSection} aria-label="ConnectWise patch tickets">
    <h3>ConnectWise patch tickets</h3>
    {settings && !settings.configured && <p className={styles.resultNote}>Open <strong>Connections → ConnectWise</strong> on the dashboard to enter your keys and load your actual boards. Manual downloads remain available.</p>}
    {packet && !requestId && <p className={styles.resultNote}>Prepare a fresh request to save its report and enable ticket creation.</p>}
    {packet?.tenantIds?.length && packet.tenantIds.length > 1 ? <p className={styles.patchError}>This report spans {packet.tenantIds.length} CrowdStrike tenants. Select one tenant above and prepare its report before sending a customer ticket.</p> : null}
    {canCreate && !review && <button type="button" className={styles.primaryButton} disabled={Boolean(busy)} onClick={() => { setReview(true); setError(""); }}>Review ConnectWise ticket</button>}
    {review && canCreate && <form className="mt-5 space-y-4" onSubmit={e => { e.preventDefault(); void action(requestId!, "create", { routing: { ...routing, companyId }, title, body, connectionRevision: settings?.revision }); }}>
      <p className={styles.resultNote}>{packet.hostCount.toLocaleString()} devices · CrowdStrike tenant <span className="break-all">{packet.tenantIds[0]}</span><br />Collected {new Date(packet.collectedAt).toLocaleString()}. Choose the ConnectWise company that owns this scope.</p>
      {requests.some(r => r.ticketId && !r.closed) && <p className={styles.patchWarnings}>There are already linked tickets for this CVE below. Check their company and device count before creating another request.</p>}
      <ConnectWiseSelect label="ConnectWise company" kind="companies" value={companyId} onChange={setCompanyId} revision={settings?.revision} disabled={Boolean(busy)} />
      <ConnectWiseRouting value={routing} onChange={setRouting} revision={settings?.revision} disabled={Boolean(busy)} />
      <label className={styles.patchLabel}>Ticket title<input required maxLength={100} value={title} onChange={e => setTitle(e.target.value)} disabled={Boolean(busy)} /></label>
      <label className={styles.patchLabel}>Ticket contents<textarea required maxLength={200000} value={body} onChange={e => setBody(e.target.value)} rows={10} disabled={Boolean(busy)} /></label>
      <p className={styles.resultNote}>{packet.cve}-patch-request.csv will be attached with the complete asset list and recommended remediations. Asset names are kept in the CSV.</p>
      <div className={styles.patchActions}><button type="submit" className={styles.primaryButton} disabled={Boolean(busy)}>{busy === "create" ? "Creating ticket…" : "Create ConnectWise ticket"}</button><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => setReview(false)}>Back</button></div>
    </form>}
    {current && !["prepared", "failed"].includes(current.state) && <div className="mt-4 rounded-xl border border-zinc-700 p-4" aria-live="polite">
      <p className="font-medium text-zinc-100">{patchTicketState(current)}{current.ticketId ? ` · #${current.ticketId}` : ""}</p>
      <p className={styles.resultNote}>{current.company ?? "Company selection saved"} · {current.board ?? "Board selection saved"} · {current.hostCount.toLocaleString()} devices</p>
      {current.ticketStatus && <p className={styles.resultNote}>ConnectWise status: {current.ticketStatus}. {current.fixVerifiedState === "verified" ? `CrowdStrike confirmed no open findings for this CVE on the scoped devices as of ${new Date(current.fixVerifiedAt!).toLocaleString()}.`
        : current.fixVerifiedState === "still_open" ? `CrowdStrike still shows this CVE open on ${current.fixStillOpenCount} of the scoped devices as of ${new Date(current.fixVerifiedAt!).toLocaleString()}.`
        : "CrowdStrike fix verification has not been performed."}</p>}
      <div className={styles.patchActions}>
        {current.ticketUrl && <a className={styles.button} href={current.ticketUrl} target="_blank" rel="noopener noreferrer">Open ticket #{current.ticketId}</a>}
        {current.state === "uncertain" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action(current.id, "reconcile")}>Check creation outcome</button>}
        {current.ticketId && current.attachmentState === "pending" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action(current.id, "retry-attachment")}>Retry CSV attachment</button>}
        {current.ticketId && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action(current.id, "check-status")}>Check ConnectWise status</button>}
        {current.ticketId && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={verifyFix}>{busy === "verify-fix" ? "Verifying…" : "Verify fix in CrowdStrike"}</button>}
      </div>
      {current.error && <p className={styles.patchError}>{current.error}</p>}
    </div>}
    {current?.state === "failed" && current.error && <p className={styles.patchError}>{current.error}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
    <div className="mt-5 flex flex-wrap items-center justify-between gap-2"><h4 className="text-sm font-medium">Saved requests for this CVE</h4><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => { void reload().then(rows => { if (current) setCurrent(rows.find(r => r.id === current.id) ?? current); }).catch(e => setError(e.message)); }}>Refresh history</button></div>
    {requests.length === 0 ? <p className={styles.resultNote}>No saved requests yet. Preparing a report saves a draft; only creating a ticket records a ConnectWise ticket number.</p> : <ul className="mt-3 space-y-3">
      {requests.map(row => <li key={row.id} className="rounded-lg border border-zinc-800 p-3">
        <p className="text-sm text-zinc-100">{row.ticketId ? `#${row.ticketId} · ` : ""}{patchTicketState(row)}</p>
        <p className={styles.resultNote}>{row.company ?? "No company selected"} · {row.hostCount.toLocaleString()} devices<br />{new Date(row.preparedAt).toLocaleString()} · {row.createdBy ?? row.preparedBy}</p>
        <div className="mt-2 flex flex-wrap gap-2"><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => resume(row.id)}>Open saved request</button>{row.ticketUrl && <a href={row.ticketUrl} target="_blank" rel="noopener noreferrer" className={styles.button}>Open ticket</a>}</div>
      </li>)}
    </ul>}
  </section>;
}
