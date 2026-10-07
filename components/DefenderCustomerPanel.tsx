"use client";
import React, { useEffect, useState } from "react";
import Link from "next/link";
import { ghostButtonClass } from "./ui";
import type { DefenderSummary } from "@/lib/defender-store";
import type { DefenderRecord, DefenderDevice } from "@/lib/defender-client";

type Row = { cve: string; severity: string; cvss: number | null; devices: number; findings: number; record: DefenderRecord & DefenderDevice };
type Results = { platformPublished:boolean; configured:boolean; summary: DefenderSummary | null; rows: Row[]; total: number; updatedAt: string | null;
  history: { day: string; summary: DefenderSummary }[] };
const number = (value: number) => value.toLocaleString();
export async function defenderFetch(url: string, init?: RequestInit) {
  const response = await fetch(url, { cache:"no-store", ...init });
  let body;
  try { body = await response.json(); } catch { throw new Error("The server did not return a valid response. Retry shortly."); }
  if (!response.ok) throw new Error(body.error || "Request failed.");
  return body;
}
export default function DefenderCustomerPanel({ companyId, refreshKey = "", hideUnconfigured = false }: { companyId: string; refreshKey?: string; hideUnconfigured?: boolean }) {
  const [view,setView] = useState("cves"), [offset,setOffset] = useState(0), [cve,setCve] = useState("");
  const [result,setResult] = useState<Results | null>(null), [error,setError] = useState(""), [loading,setLoading] = useState(true);
  const [loadedKey,setLoadedKey] = useState("");
  const queryKey = `${companyId}:${view}:${offset}:${cve}`;
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError("");
    defenderFetch(`/api/defender/results?${new URLSearchParams({ companyId,view,offset:String(offset),cve })}`, { signal:controller.signal })
      .then(data => { if (!controller.signal.aborted) { setResult(data); setLoadedKey(queryKey); } })
      .catch(err => { if (!controller.signal.aborted) setError(err.message); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  },[companyId,view,offset,cve,refreshKey]);
  const summary = result?.summary;
  const switchView = (next: string, filter = "") => { setView(next); setCve(filter); setOffset(0); };
  if (hideUnconfigured && !result?.configured && !error) return null;
  return <section aria-label="Microsoft Defender customer data" className="space-y-4 rounded-2xl border border-zinc-800 bg-[#090909] p-5">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="text-lg font-semibold text-white">Microsoft Defender</h2>
        <p className="text-sm text-zinc-300">Customer-scoped vulnerability and device data from the last completed import.</p></div>
      <Link className={ghostButtonClass} href={`/defender?companyId=${encodeURIComponent(companyId)}`}>Manage connection</Link>
    </div>
    {error && <p role="alert" className="text-sm text-red-300">{error} Previously loaded results, if any, are retained.</p>}
    {loading && <p role="status" className="text-sm text-zinc-300">Loading saved Defender results…</p>}
    {!loading && !error && !summary && <p className="text-sm text-zinc-300">No completed Defender import yet. Configure the connection and select Sync now.</p>}
    {summary && <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[
        ["Open vulnerability instances",summary.findings],["Unique CVEs",summary.cves],
        ["Affected devices",summary.affectedDevices],["Inventory devices",summary.inventoryDevices],
      ].map(([label,value]) => <div key={label} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
        <p className="text-sm text-zinc-300">{label}</p><p className="mt-1 text-2xl font-semibold text-white">{number(Number(value))}</p></div>)}</div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">{["CRITICAL","HIGH","MEDIUM","LOW","NONE","UNKNOWN"].map(level =>
        <div key={level} className="border-l-2 border-[#b30e14] pl-3"><p className="text-xs text-zinc-300">{level}</p><p className="text-xl text-white">{number(summary.severity[level] || 0)}</p></div>)}</div>
      <p className="text-xs text-zinc-300">Instances count each affected device, CVE and software version. Unique CVEs count each CVE once. Scores are Microsoft CVSS, not CrowdStrike ExPRT.</p>
      <p className="text-xs text-zinc-300">{result?.platformPublished ? "This import is included in customer findings and executive reports. Risk scores and patch-review candidates update in the background." : "This completed import is waiting to be published to platform findings. Previously published platform data remains available."} Platform totals group findings by device and CVE.</p>
      <Link className={ghostButtonClass} href={`/reporting?companyId=${encodeURIComponent(companyId)}`}>Open customer reporting and patch review</Link>
      <div className="flex flex-wrap gap-2" aria-label="Defender result views">{[["cves","CVEs by affected devices"],["findings","Findings & remediations"],["devices","Devices"]].map(([key,label]) =>
        <button key={key} type="button" aria-pressed={view === key} onClick={() => switchView(key)} className={`${ghostButtonClass} ${view === key ? "border-red-600 text-white" : ""}`}>{label}</button>)}</div>
      {cve && <div className="flex items-center gap-3 text-sm text-zinc-200">Showing {cve}<button className={ghostButtonClass} onClick={() => switchView("findings")}>Clear filter</button></div>}
      <div className="max-h-[520px] overflow-auto rounded-xl border border-zinc-800" aria-busy={loading}>
        <table className="w-full text-left text-sm text-zinc-200"><thead className="sticky top-0 bg-zinc-900 text-zinc-300"><tr>
          {(view === "cves" ? ["CVE","Severity","CVSS","Affected devices","Instances"] : view === "devices" ? ["Device","OS","Last IP","Instances","Last seen"] : ["CVE / device","Severity / CVSS","Software","Recommended update","First / last seen"]).map(label => <th key={label} className="p-3 font-medium">{label}</th>)}
        </tr></thead><tbody className={loading ? "opacity-50" : ""}>
          {(loadedKey === queryKey ? result.rows : []).map((row,index) => <tr key={row.cve || row.record?.sourceId || row.record?.deviceId || index} className="border-t border-zinc-800 align-top hover:bg-zinc-900/60">
            {view === "cves" ? <><td className="p-3"><button disabled={loading} onClick={() => switchView("findings",row.cve)} className="text-red-300 underline underline-offset-4">{row.cve}</button></td><td className="p-3">{row.severity}</td><td className="p-3">{row.cvss ?? "Unknown"}</td><td className="p-3">{number(row.devices)}</td><td className="p-3">{number(row.findings)}</td></> :
              view === "devices" ? <><td className="p-3">{row.record.hostname}<span className="mt-1 block break-all text-xs text-zinc-400">{row.record.deviceId}</span></td><td className="p-3">{row.record.os || "Unknown"}</td><td className="p-3">{row.record.ip || "Unknown"}</td><td className="p-3">{number(row.findings)}</td><td className="p-3">{row.record.lastSeen || "Unknown"}</td></> :
              <><td className="p-3">{row.record.cve}<span className="mt-1 block">{row.record.hostname}</span><span className="block break-all text-xs text-zinc-400">{row.record.deviceId}</span></td>
                <td className="p-3">{row.record.severity}<span className="block">{row.record.cvss ?? "Unknown"}</span><span className="block text-xs">{row.record.exploitability}</span></td>
                <td className="p-3">{row.record.softwareVendor} {row.record.softwareName}<span className="block">{row.record.softwareVersion}</span></td>
                <td className="min-w-64 max-w-lg p-3">{row.record.remediation}<span className="mt-1 block text-xs text-zinc-300">{row.record.remediationId}</span><span className="block break-all text-xs text-zinc-400">{row.record.recommendationId}</span></td>
                <td className="p-3 text-xs">{row.record.firstSeen || "Unknown"}<span className="mt-1 block">{row.record.lastSeen || "Unknown"}</span></td></>}
          </tr>)}
          {!result.rows.length && <tr><td colSpan={5} className="p-5 text-zinc-300">No matching records.</td></tr>}
        </tbody></table>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-zinc-300"><span>{number(offset + (result.total ? 1 : 0))}–{number(Math.min(offset + 50,result.total))} of {number(result.total)}</span>
        <div className="flex gap-2"><button className={ghostButtonClass} disabled={loading || offset === 0} onClick={() => setOffset(Math.max(0,offset-50))}>Previous</button><button className={ghostButtonClass} disabled={loading || offset+50 >= result.total} onClick={() => setOffset(offset+50)}>Next</button></div></div>
      <details className="text-sm text-zinc-300"><summary className="cursor-pointer">Daily open-count history · {result.history.length} observed days</summary>
        <p className="my-2">One observation per UTC day with a successful import. Missing days are not recorded as zero.</p>
        <div className="max-h-60 overflow-auto"><table className="w-full text-left"><thead><tr><th className="p-2">UTC day</th><th>Instances</th><th>Unique CVEs</th><th>Affected devices</th></tr></thead><tbody>{result.history.map(day => <tr key={day.day}><td className="p-2">{day.day}</td><td>{number(day.summary.findings)}</td><td>{number(day.summary.cves)}</td><td>{number(day.summary.affectedDevices)}</td></tr>)}</tbody></table></div>
      </details>
      <p className="text-xs text-zinc-300">Last successful import: {result.updatedAt ? new Date(result.updatedAt).toLocaleString() : "Not yet available"}. Microsoft export data may precede the import time.</p>
    </>}
  </section>;
}
