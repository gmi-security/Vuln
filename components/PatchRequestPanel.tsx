"use client";

import { useEffect, useId, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { PatchRequest } from "@/lib/patch-request";
import styles from "./QueryDashboard.module.css";

type Job = { jobId: string; status: string; error?: string; patchRequest?: PatchRequest };

export default function PatchRequestPanel({ cve }: { cve: string }) {
  const [packet, setPacket] = useState<PatchRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const generation = useRef(0);
  const fieldsId = useId();
  useEffect(() => () => { generation.current++; }, []);

  async function prepare() {
    const current = ++generation.current;
    setBusy(true); setError(""); setMessage("Collecting all matching CrowdStrike pages. This can take several minutes.");
    try {
      let job = await dashboardRequest<Job>("patch-requests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cve }) });
      const deadline = Date.now() + 15 * 60_000;
      while (["queued", "running"].includes(job.status)) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (generation.current !== current) return;
        if (Date.now() >= deadline) throw new Error("The preparation job expired. Please prepare the request again.");
        job = await dashboardRequest<Job>(`jobs/${job.jobId}`);
      }
      if (generation.current !== current) return;
      if (job.status !== "succeeded" || !job.patchRequest || job.patchRequest.cve !== cve) throw new Error(job.error || "The patch request could not be prepared. Please retry.");
      setPacket(job.patchRequest); setMessage("Patch request ready. Download the CSV and copy the ticket contents into ConnectWise.");
    } catch (cause) {
      if (generation.current === current) { setError(cause instanceof Error ? cause.message : "Preparation failed. Please retry."); setMessage(""); }
    } finally { if (generation.current === current) setBusy(false); }
  }

  function download(contents: string, extension: string, mime: string) {
    const url = URL.createObjectURL(new Blob([contents], { type: mime }));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = `${cve}-patch-request.${extension}`; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function copy() {
    if (!packet) return;
    try { await navigator.clipboard.writeText(`${packet.title}\n\n${packet.body}`); setMessage("Ticket contents copied. Attach the CSV when creating the ConnectWise ticket."); }
    catch { setMessage("Clipboard access is unavailable. Select and copy the text below, or download the ticket text."); }
  }

  return <section className={styles.patchSection} aria-label="Prepare patch request">
    <h3>Prepare patch request</h3>
    <p className={styles.resultNote}>Collect all open/reopened findings for this CVE visible to your CrowdStrike connection, including suppressed findings. Tile filters and top-row limits do not apply.</p>
    <button type="button" className={styles.button} disabled={busy} onClick={prepare}>{busy ? "Preparing patch request…" : packet ? "Prepare fresh request" : "Prepare patch request"}</button>
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {packet && <>
      <p className={styles.resultNote}><strong>{packet.hostCount.toLocaleString()} hosts · {packet.findingCount.toLocaleString()} findings</strong><br />Collected {packet.collectedAt}. {packet.csvRows.toLocaleString()} CSV rows; applications and patch alternatives may produce multiple rows per host.</p>
      {packet.warnings.length > 0 && <ul className={styles.patchWarnings}>{packet.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>}
      <div className={styles.patchActions}>
        <button type="button" className={styles.button} onClick={() => download(packet.csv, "csv", "text/csv;charset=utf-8")}>Download CSV</button>
        <button type="button" className={styles.button} onClick={copy}>Copy ticket contents</button>
        <button type="button" className={styles.button} onClick={() => download(`${packet.title}\n\n${packet.body}`, "txt", "text/plain;charset=utf-8")}>Download ticket text</button>
      </div>
      <div className={styles.patchLabel}><label htmlFor={`${fieldsId}-title`}>Ticket title</label><input id={`${fieldsId}-title`} readOnly value={packet.title} /></div>
      <div className={styles.patchLabel}><label htmlFor={`${fieldsId}-body`}>Ticket contents</label><textarea id={`${fieldsId}-body`} readOnly value={packet.body} rows={14} /></div>
      <p className={styles.resultNote}>Create the ConnectWise ticket manually and attach the CSV. No ticket has been sent and no patching has been started.</p>
    </>}
  </section>;
}
