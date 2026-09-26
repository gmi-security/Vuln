"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import { automatedGroupTicketBody, patchGroupTicketState, type PatchGroupTicketSummary } from "@/lib/patch-group-ticket-types";
import type { PatchGroup } from "@/lib/patch-request";
import type { CWDefaults } from "@/lib/connectwise-client";
import { ConnectWiseRouting, ConnectWiseSelect, type CWSettings } from "@/components/ConnectWiseFields";
import styles from "./QueryDashboard.module.css";

export default function ConnectWiseGroupTicket({ group, requestId }: { group: PatchGroup; requestId: string }) {
  const [settings, setSettings] = useState<CWSettings | null>(null);
  const [current, setCurrent] = useState<PatchGroupTicketSummary | null>(null), [review, setReview] = useState(false);
  const [routing, setRouting] = useState<CWDefaults>({}), [companyId, setCompanyId] = useState<number>();
  const [title, setTitle] = useState(group.ticketTitle), [body, setBody] = useState(automatedGroupTicketBody(group)), [busy, setBusy] = useState("");
  const [error, setError] = useState(""), [message, setMessage] = useState("");
  const generation = useRef(0);
  const reload = useCallback(async () => {
    const data = await dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${requestId}`);
    setCurrent(data.request);
    return data.request;
  }, [requestId]);
  useEffect(() => {
    let live = true;
    Promise.all([dashboardRequest<CWSettings>("connectwise"), dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${requestId}`)])
      .then(([config, data]) => { if (live) { setSettings(config); setRouting(config.defaults); setCurrent(data.request); } })
      .catch(e => { if (live) setError(e.message); });
    return () => { live = false; generation.current++; };
  }, [requestId]);
  async function track(token: number) {
    for (let attempt = 0; attempt < 95; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      if (generation.current !== token) return;
      const data = await dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${requestId}`);
      if (generation.current !== token) return;
      setCurrent(data.request);
      if (data.request.state !== "creating" && data.request.attachmentState !== "uploading" && !(attempt < 2 && data.request.state === "created" && data.request.attachmentState === "pending" && !data.request.error)) return;
    }
    setMessage("The operation is still pending. Its saved request can be checked again below.");
  }
  async function action(operation: string, extra: Record<string, unknown> = {}) {
    const token = ++generation.current; setBusy(operation); setError(""); setMessage("");
    try {
      const data = await dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${requestId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: operation, ...extra }) });
      if (generation.current !== token) return;
      setCurrent(data.request); setReview(false);
      if (operation === "create" || operation === "retry-attachment") await track(token); else await reload();
    } catch (e) { if (generation.current === token) { setError(e instanceof Error ? e.message : "Could not process this request."); void reload().catch(() => {}); } }
    finally { if (generation.current === token) setBusy(""); }
  }
  const canCreate = settings?.configured && (!current || ["prepared", "failed"].includes(current.state));
  return <section className="mt-4 rounded-xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-4" aria-label="ConnectWise ticket for this patch">
    <h4 className="text-sm font-medium text-zinc-100">ConnectWise ticket</h4>
    {settings && !settings.configured && <p className={styles.resultNote}>Open <strong>Connections → ConnectWise</strong> to enter your keys and load your boards.</p>}
    {canCreate && !review && <button type="button" className={styles.primaryButton} disabled={Boolean(busy)} onClick={() => { setReview(true); setError(""); }}>Review ConnectWise ticket</button>}
    {review && canCreate && <form className="mt-4 space-y-4" onSubmit={e => { e.preventDefault(); void action("create", { routing: { ...routing, companyId }, title, body, connectionRevision: settings?.revision }); }}>
      <p className={styles.resultNote}>{group.deviceCount.toLocaleString()} devices · resolves {group.cves.join(", ")} · CrowdStrike tenant <span className="break-all">{group.tenantId}</span><br />Choose the ConnectWise company that owns this scope.</p>
      <ConnectWiseSelect label="ConnectWise company" kind="companies" value={companyId} onChange={setCompanyId} revision={settings?.revision} disabled={Boolean(busy)} />
      <ConnectWiseRouting value={routing} onChange={setRouting} revision={settings?.revision} disabled={Boolean(busy)} />
      <label className={styles.patchLabel}>Ticket title<input required maxLength={100} value={title} onChange={e => setTitle(e.target.value)} disabled={Boolean(busy)} /></label>
      <label className={styles.patchLabel}>Ticket contents<textarea required maxLength={200000} value={body} onChange={e => setBody(e.target.value)} rows={10} disabled={Boolean(busy)} /></label>
      <p className={styles.resultNote}>{group.label}-patch-request.csv will be attached with the affected device list. One ticket covers every CVE this patch resolves.</p>
      <div className={styles.patchActions}><button type="submit" className={styles.primaryButton} disabled={Boolean(busy)}>{busy === "create" ? "Creating ticket…" : "Create ConnectWise ticket"}</button><button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => setReview(false)}>Back</button></div>
    </form>}
    {current && !["prepared", "failed"].includes(current.state) && <div className="mt-4 rounded-lg border border-zinc-700 p-3" aria-live="polite">
      <p className="font-medium text-zinc-100">{patchGroupTicketState(current)}{current.ticketId ? ` · #${current.ticketId}` : ""}</p>
      <p className={styles.resultNote}>{current.company ?? "Company selection saved"} · {current.board ?? "Board selection saved"} · {current.hostCount.toLocaleString()} devices</p>
      {current.ticketStatus && <p className={styles.resultNote}>ConnectWise status: {current.ticketStatus}. CrowdStrike fix verification has not been performed.</p>}
      <div className={styles.patchActions}>
        {current.ticketUrl && <a className={styles.button} href={current.ticketUrl} target="_blank" rel="noopener noreferrer">Open ticket #{current.ticketId}</a>}
        {current.state === "uncertain" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("reconcile")}>Check creation outcome</button>}
        {current.ticketId && current.attachmentState === "pending" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("retry-attachment")}>Retry CSV attachment</button>}
        {current.ticketId && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("check-status")}>Check ConnectWise status</button>}
      </div>
      {current.error && <p className={styles.patchError}>{current.error}</p>}
    </div>}
    {current?.state === "failed" && current.error && <p className={styles.patchError}>{current.error}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
  </section>;
}
