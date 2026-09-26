"use client";

import { useEffect, useRef, useState } from "react";
import { dashboardRequest } from "@/lib/dashboard-browser-client";
import type { PatchConsolidation } from "@/lib/patch-request";
import styles from "./QueryDashboard.module.css";

type Job = { jobId: string; status: string; error?: string; consolidation?: PatchConsolidation };

export default function PatchConsolidationPanel({ cves }: { cves: string[] }) {
  const [packet, setPacket] = useState<PatchConsolidation | null>(null);
  const [tenantId, setTenantId] = useState("");
  const [tenants, setTenants] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; }, []);

  async function prepare() {
    const current = ++generation.current;
    setBusy(true); setError(""); setMessage("Collecting all matching CrowdStrike pages for each CVE. This can take several minutes.");
    try {
      let job = await dashboardRequest<Job>("consolidations", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cves, ...(tenantId ? { tenantId } : {}) }) });
      const deadline = Date.now() + 15 * 60_000;
      while (["queued", "running"].includes(job.status)) {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        if (generation.current !== current) return;
        if (Date.now() >= deadline) throw new Error("The preparation job expired. Please prepare the plan again.");
        job = await dashboardRequest<Job>(`jobs/${job.jobId}`);
      }
      if (generation.current !== current) return;
      if (job.status !== "succeeded" || !job.consolidation) throw new Error(job.error || "The consolidation could not be prepared. Please retry.");
      setPacket(job.consolidation);
      setTenants(old => [...new Set([...old, ...(job.consolidation?.tenantIds ?? [])])].sort());
      setMessage("Consolidated patch plan ready. Work the ranked list top to bottom.");
    } catch (cause) {
      if (generation.current === current) { setError(cause instanceof Error ? cause.message : "Preparation failed. Please retry."); setMessage(""); }
    } finally { if (generation.current === current) setBusy(false); }
  }

  function download(contents: string, extension: string, mime: string) {
    const url = URL.createObjectURL(new Blob([contents], { type: mime }));
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = `patch-consolidation.${extension}`; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function copy() {
    if (!packet) return;
    try { await navigator.clipboard.writeText(`${packet.title}\n\n${packet.body}`); setMessage("Report copied to clipboard."); }
    catch { setMessage("Clipboard access is unavailable. Download the report text instead."); }
  }

  const maxDevices = Math.max(1, ...(packet?.groups.map((g) => g.deviceCount) ?? [1]));

  return <section className={styles.patchSection} aria-label="Consolidate patch plan">
    <h3>Consolidate into a patch plan</h3>
    <p className={styles.resultNote}>Group {cves.length} CVEs by the CrowdStrike remediation that actually resolves them, ranked by devices cleared per patch action — the most bang for the buck first.</p>
    {tenants.length > 1 && <label className={`${styles.patchLabel} block`}>CrowdStrike tenant
      <select className="mt-2 block w-full rounded-lg border border-zinc-600 bg-zinc-900 p-3 text-zinc-100" value={tenantId} onChange={e => setTenantId(e.target.value)} disabled={busy}>
        <option value="">All visible tenants</option>{tenants.map(id => <option key={id} value={id}>{id}</option>)}
      </select>
    </label>}
    <button type="button" className={styles.button} disabled={busy} onClick={prepare}>{busy ? "Building plan…" : packet ? "Rebuild plan" : "Build consolidated patch plan"}</button>
    {message && <p role="status" className={styles.resultNote}>{message}</p>}
    {error && <p role="alert" className={styles.patchError}>{error}</p>}
    {packet && <>
      <p className={styles.resultNote}>
        <strong>{packet.totalDevices.toLocaleString()} devices · {packet.totalFindings.toLocaleString()} open findings · {packet.groups.length} patch action{packet.groups.length === 1 ? "" : "s"}</strong>
        <br />Collected {packet.collectedAt}.
      </p>
      {packet.tenantIds.length > 1 && <p role="alert" className={styles.patchError}>This spans {packet.tenantIds.length} CrowdStrike tenants ({packet.tenantIds.join(", ")}). Each ranked action below is scoped to one tenant (shown on its card) — do not combine devices across tenants into one ticket or maintenance window. Use the tenant picker above to narrow the report to one customer.</p>}
      {packet.unmapped.length > 0 && <ul className={styles.patchWarnings}>
        {packet.unmapped.map((u) => <li key={u.cve}>{u.cve}: no actionable remediation supplied by CrowdStrike ({u.deviceCount.toLocaleString()} affected device{u.deviceCount === 1 ? "" : "s"}). Review individually in Falcon.</li>)}
      </ul>}
      <div className={styles.patchActions}>
        <button type="button" className={styles.button} onClick={() => download(packet.csv, "csv", "text/csv;charset=utf-8")}>Download CSV</button>
        <button type="button" className={styles.button} onClick={copy}>Copy report</button>
        <button type="button" className={styles.button} onClick={() => download(`${packet.title}\n\n${packet.body}`, "txt", "text/plain;charset=utf-8")}>Download report text</button>
      </div>
      <div className="mt-4 space-y-3">
        {packet.groups.map((group, index) => {
          const share = packet.totalDevices > 0 ? Math.round((group.deviceCount / packet.totalDevices) * 1000) / 10 : 0;
          return (
            <div key={group.remediationId} className="rounded-xl border border-[rgba(179,14,20,0.14)] bg-[#0a0a0a] p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-zinc-800 bg-zinc-950 px-2 py-0.5 text-[11px] font-semibold text-zinc-400">#{index + 1}</span>
                    <span className="font-medium text-white">{group.title || "Recommended remediation"}</span>
                    {packet.tenantIds.length > 1 && <span className="rounded-full border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-[11px] text-zinc-400">Tenant {group.tenantId}</span>}
                  </div>
                  <p className="mt-2 text-sm text-zinc-300">{group.action || "No action text supplied by CrowdStrike."}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {group.cves.map((cve) => (
                      <span key={cve} className="rounded-full border border-[rgba(179,14,20,0.4)] bg-[rgba(179,14,20,0.12)] px-2.5 py-0.5 text-[11px] text-[#ff8f96]">{cve}</span>
                    ))}
                  </div>
                  {(group.reference || group.vendorUrl || group.published) && (
                    <p className="mt-2 text-xs text-zinc-500">
                      {group.reference && <>Ref: {group.reference} </>}
                      {group.published && <>· Published {group.published} </>}
                    </p>
                  )}
                </div>
                <div className="shrink-0 text-right">
                  <div className="text-2xl font-semibold text-white">{group.deviceCount.toLocaleString()}</div>
                  <div className="text-[11px] uppercase tracking-[0.18em] text-zinc-600">devices</div>
                  <div className="mt-2 h-1.5 w-24 overflow-hidden rounded-full bg-zinc-900" aria-hidden="true">
                    <span className="block h-full rounded-full bg-[#b30e14]" style={{ width: `${(group.deviceCount / maxDevices) * 100}%` }} />
                  </div>
                  <div className="mt-1 text-[11px] text-zinc-500">{share}% of scope · {group.cves.length} CVE{group.cves.length === 1 ? "" : "s"} · {group.findingCount.toLocaleString()} findings</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <p className={styles.resultNote}>No ticket has been sent to ConnectWise and no patching has been started.</p>
    </>}
  </section>;
}
