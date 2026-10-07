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
  const [editingPriority, setEditingPriority] = useState(false), [priorityDraft, setPriorityDraft] = useState<number>();
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
  async function action(operation: string, extra: Record<string, unknown> = {}): Promise<boolean> {
    const token = ++generation.current; setBusy(operation); setError(""); setMessage(""); let ok = false;
    try {
      const data = await dashboardRequest<{ request: PatchGroupTicketSummary }>(`patch-group-tickets/${requestId}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: operation, ...extra }) });
      if (generation.current !== token) return false;
      setCurrent(data.request); setReview(false); ok = true;
      if (operation === "create" || operation === "retry-attachment") await track(token); else await reload();
    } catch (e) { if (generation.current === token) { setError(e instanceof Error ? e.message : "Could not process this request."); void reload().catch(() => {}); } }
    finally { if (generation.current === token) setBusy(""); }
    return ok;
  }
  async function verifyFix() {
    const token = ++generation.current; setBusy("verify-fix"); setError(""); setMessage("Checking CrowdStrike for these CVEs' current status. This can take a minute or two.");
    try {
      let job = await dashboardRequest<{ jobId: string; status: string; error?: string; ticket?: { request: PatchGroupTicketSummary } }>("verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ticketKind: "group", ticketId: requestId }) });
      const deadline = Date.now() + 5 * 60_000;
      while (["queued", "running"].includes(job.status)) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        if (generation.current !== token) return;
        if (Date.now() >= deadline) throw new Error("The verification job expired. Please try again.");
        job = await dashboardRequest(`jobs/${job.jobId}`);
      }
      if (generation.current !== token) return;
      if (job.status !== "succeeded" || !job.ticket) throw new Error(job.error || "Verification failed. Please retry.");
      setCurrent(job.ticket.request); setMessage("Verification complete.");
    } catch (e) { if (generation.current === token) { setError(e instanceof Error ? e.message : "Verification failed. Please retry."); setMessage(""); } }
    finally { if (generation.current === token) setBusy(""); }
  }
  const defenderOnly = group.source === "stored-findings" && group.connectors?.length === 1 && group.connectors[0] === "defender";
  const canCreate = settings?.configured && current?.reviewState === "approved" && ["prepared", "failed"].includes(current.state);
  return <section className="mt-4 rounded-xl border border-[rgba(179,14,20,0.14)] bg-[#050505] p-4" aria-label="ConnectWise ticket for this patch">
    <h4 className="text-sm font-medium text-zinc-100">ConnectWise ticket</h4>
    {current && current.reviewState !== "approved" && !current.ticketId && <p className={styles.resultNote}>This draft must be approved in the review queue before a ticket can be sent.</p>}
    {settings && !settings.configured && <p className={styles.resultNote}>Open <strong>Connections → ConnectWise</strong> to enter your keys and load your boards.</p>}
    {canCreate && !review && <button type="button" className={styles.primaryButton} disabled={Boolean(busy)} onClick={() => { setReview(true); setError(""); }}>Review ConnectWise ticket</button>}
    {review && canCreate && <form className="mt-4 space-y-4" onSubmit={e => { e.preventDefault(); void action("create", { routing: { ...routing, companyId }, title, body, connectionRevision: settings?.revision }); }}>
      <p className={styles.resultNote}>{group.deviceCount.toLocaleString()} {group.source === "stored-findings" ? "assets" : "devices"} · resolves {group.cves.join(", ")} · {group.source === "stored-findings" ? `Customer ${group.companyName} · sources ${group.connectors?.join(", ")}` : <>CrowdStrike tenant <span className="break-all">{group.tenantId}</span></>}<br />Choose the ConnectWise company that owns this scope.</p>
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
      {current.ticketStatus && <p className={styles.resultNote}>ConnectWise status: {current.ticketStatus}. {group.source === "stored-findings" ? (defenderOnly && current.fixVerifiedAt ? `Defender verification: ${current.fixVerifiedState === "verified" ? "no remaining findings" : `${current.fixStillOpenCount} devices still affected`}, using the import from ${new Date(current.fixVerifiedAt).toLocaleString()}.` : "Sync the source scanner after patching, then verify the fix.") : current.fixVerifiedState === "verified" ? `CrowdStrike confirmed no open findings for these CVEs on the scoped devices as of ${new Date(current.fixVerifiedAt!).toLocaleString()}.`
        : current.fixVerifiedState === "still_open" ? `CrowdStrike still shows these CVEs open on ${current.fixStillOpenCount} of the scoped devices as of ${new Date(current.fixVerifiedAt!).toLocaleString()}.`
        : "CrowdStrike fix verification has not been performed."}</p>}
      {current.ticketId && <div className="mt-2">
        {!editingPriority ? <p className={styles.resultNote}>Priority: {current.priorityName ?? "Unknown — check status to load it"}
          <button type="button" className={`${styles.button} ml-2`} disabled={Boolean(busy)} onClick={() => { setPriorityDraft(current.priorityId ?? undefined); setEditingPriority(true); }}>Raise or lower</button>
          {current.slaEscalations > 0 && <span className="ml-2 text-[#ff8f96]">· auto-escalated ×{current.slaEscalations} for sitting open past SLA</span>}</p>
          : <div className="mt-2 flex flex-wrap items-end gap-2">
            <div className="min-w-[12rem]"><ConnectWiseSelect label="Priority" kind="priorities" value={priorityDraft} onChange={setPriorityDraft} revision={settings?.revision} disabled={Boolean(busy)} /></div>
            <button type="button" className={styles.primaryButton} disabled={Boolean(busy) || !priorityDraft} onClick={() => void action("set-priority", { priorityId: priorityDraft }).then(ok => { if (ok) setEditingPriority(false); })}>{busy === "set-priority" ? "Saving…" : "Save priority"}</button>
            <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => setEditingPriority(false)}>Cancel</button>
          </div>}
      </div>}
      <div className={styles.patchActions}>
        {current.ticketUrl && <a className={styles.button} href={current.ticketUrl} target="_blank" rel="noopener noreferrer">Open ticket #{current.ticketId}</a>}
        {current.state === "uncertain" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("reconcile")}>Check creation outcome</button>}
        {current.ticketId && current.attachmentState === "pending" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("retry-attachment")}>Retry CSV attachment</button>}
        {current.ticketId && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={() => action("check-status")}>Check ConnectWise status</button>}
        {current.ticketId && defenderOnly && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={()=>void action("verify-defender")}>{busy === "verify-defender" ? "Verifying..." : "Verify fix from latest Defender import"}</button>}
        {current.ticketId && group.source !== "stored-findings" && <button type="button" className={styles.button} disabled={Boolean(busy)} onClick={verifyFix}>{busy === "verify-fix" ? "Verifying…" : "Verify fix in CrowdStrike"}</button>}
      </div>
      {current.error && <p className={styles.patchError}>{current.error}</p>}
    </div>}
    {current?.state === "failed" && current.error && <p className={styles.patchError}>{current.error}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
  </section>;
}
