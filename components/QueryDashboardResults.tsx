"use client";

import { useEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import ElasticResultChart from "@/components/ElasticResultChart";
import CveText from "@/components/CveText";
import PatchRequestPanel from "@/components/PatchRequestPanel";
import PatchConsolidationPanel from "@/components/PatchConsolidationPanel";
import { canShowMetrics, columnLabel, isChartDisplay, numericColumn, type QueryDefinition, type QueryResult } from "@/lib/elastic-dashboard";
import { severityBarColor, severityClass } from "@/lib/format";
import type { Severity } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

function severity(value: string): Severity | undefined {
  return Object.keys(severityBarColor).find((key) => key.toLowerCase() === value.replace(/_cves$/i, "").toLowerCase()) as Severity | undefined;
}

export function formatResultValue(value: string | number | boolean | null, column: string): string {
  if (value === null) return "—";
  if (typeof value === "number") {
    if (column === "epss") return `${Math.round(value * 100)}%`;
    const formatted = value.toLocaleString("en-US", { maximumFractionDigits: 2 });
    return /(?:_pct|_percent|percentage)$/i.test(column) ? `${formatted}%` : formatted;
  }
  if (column === "cisa_kev" && typeof value === "boolean") return value ? "Listed" : "Not listed";
  return String(value);
}

export default function QueryDashboardResults({ result, display, chart, preparePatch = false, companyId = "" }: {
  result: QueryResult; display: QueryDefinition["display"]; chart?: QueryDefinition["chart"]; preparePatch?: boolean; companyId?: string;
}) {
  const [selected, setSelected] = useState<{ cve: string; row?: QueryResult["rows"][number] } | null>(null);
  const [consolidating, setConsolidating] = useState<string[] | null>(null);
  const [requestedPage, setRequestedPage] = useState(0);
  const tableScroll = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const consolidationDialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const consolidationTitleId = useId();
  useEffect(() => { if (selected) dialog.current?.showModal(); }, [selected]);
  useEffect(() => { if (consolidating) consolidationDialog.current?.showModal(); }, [consolidating]);
  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(result.rows.length / pageSize));
  const page = Math.min(requestedPage, pageCount - 1);
  const pageRows = result.rows.slice(page * pageSize, (page + 1) * pageSize);
  const cvesIn = (rows: QueryResult["rows"]) => [...new Set(rows.flatMap(row => row.flatMap(value =>
    typeof value === "string" ? (value.match(/\bCVE-\d{4}-\d{4,19}\b/gi) ?? []).map(cve => cve.toUpperCase()) : [])))];
  const allCves = cvesIn(result.rows);
  const pageCves = cvesIn(pageRows);
  function changePage(next: number) {
    setRequestedPage(next);
    tableScroll.current?.scrollTo({ top: 0 });
  }
  const consolidationPanel = (
    <dialog ref={consolidationDialog} className={styles.detail} aria-labelledby={consolidationTitleId} onClose={() => setConsolidating(null)} onClick={(event) => { if (event.target === event.currentTarget) consolidationDialog.current?.close(); }}>
      <div className={styles.detailBody}>
        <div className={styles.detailTop}><span>Patch consolidation</span><button type="button" className={styles.button} onClick={() => consolidationDialog.current?.close()}><X size={15} />Close</button></div>
        <h2 id={consolidationTitleId}>{consolidating?.length ?? 0} CVEs</h2>
        <p className={styles.resultNote}>{consolidating?.join(", ")}</p>
        {consolidating && <PatchConsolidationPanel key={`${companyId}-${consolidating.join(",")}`} cves={consolidating} companyId={companyId} />}
      </div>
    </dialog>
  );

  const details = (
    <dialog ref={dialog} className={styles.detail} aria-labelledby={titleId} onClose={() => setSelected(null)} onClick={(event) => { if (event.target === event.currentTarget) dialog.current?.close(); }}>
      <div className={styles.detailBody}>
        <div className={styles.detailTop}><span>CVE details</span><button type="button" className={styles.button} onClick={() => dialog.current?.close()}><X size={15} />Close</button></div>
        <h2 id={titleId}>{selected?.cve ?? "CVE details"}</h2>
        <p className={styles.resultNote}>{selected?.row ? "Snapshot of the result selected from this tile." : "CVE selected from this tile. Prepare a request for current CrowdStrike details."}</p>
        <dl className={styles.detailFields}>{selected?.row && result.columns.map((column, index) => String(selected.row![index]).toUpperCase() !== selected.cve && <div key={column.name}><dt>{columnLabel(column.name)}</dt><dd>{cell(selected.row![index], column.name)}</dd></div>)}</dl>
        {preparePatch && selected && <PatchRequestPanel key={selected.cve} cve={selected.cve} />}
      </div>
    </dialog>
  );
  if (isChartDisplay(display)) return <><ElasticResultChart result={result} definition={{ display, chart }} onCveSelect={cve => setSelected({ cve })} />{details}{consolidationPanel}</>;
  if (display !== "table" && canShowMetrics(result)) {
    const uniqueCves = result.columns.every((column) => /^(critical|high|medium|low|none|unknown)_cves$/i.test(column.name));
    const severityMetrics = result.columns.every((column) => severity(column.name) || /^(none|unknown)(_cves)?$/i.test(column.name));
    const total = severityMetrics ? result.rows[0].reduce<number>((sum, value) => sum + (typeof value === "number" ? value : 0), 0) : 0;
    return <><div className={styles.metrics}>
      {result.columns.map((column, index) => {
        const level = severity(column.name), value = result.rows[0][index];
        const share = total > 0 && typeof value === "number" ? value / total * 100 : 0;
        const color = level ? severityBarColor[level] : "#b30e14";
        return <div key={column.name} className={styles.metric}>
          <div className={styles.metricLabel}>{level && <span className={styles.dot} style={{ background: color }} />}<CveText text={columnLabel(column.name).replace(/ cves$/i, " CVEs")} onSelect={cve => setSelected({ cve })} /></div>
          <div className={styles.metricValue}>{formatResultValue(value, column.name)}</div>
          {severityMetrics && <><div className={styles.track} aria-hidden="true"><span style={{ width: `${share}%`, background: color }} /></div>
            <div className={styles.metricNote}>{total > 0 ? `${share.toFixed(1)}% of ${uniqueCves ? "unique CVEs" : "returned findings"}` : uniqueCves ? "No open CVEs" : "No findings"}</div></>}
        </div>;
      })}
    </div>{details}{consolidationPanel}</>;
  }
  const hasCves = result.rows.some(row => row.some(value => typeof value === "string" && /\bCVE-\d{4}-\d{4,19}\b/i.test(value)));
  const devicesIndex = result.columns.findIndex((column) => column.name === "affected_devices");
  const maxDevices = Math.max(1, ...result.rows.map((row) => typeof row[devicesIndex] === "number" ? row[devicesIndex] as number : 0));
  function cell(value: QueryResult["rows"][number][number], name: string) {
    const level = /severity/i.test(name) && typeof value === "string" ? severity(value) : undefined;
    if (level) return <span className={`${styles.badge} ${severityClass[level]}`}>{level}</span>;
    if (name === "cisa_kev" && value === true) return <span className="text-[#ff4d57]">Listed</span>;
    if (typeof value === "string") return <CveText text={value} onSelect={cve => setSelected({ cve, row: selected?.row })} />;
    return formatResultValue(value, name);
  }
  return <div>
    {preparePatch && allCves.length >= 2 && (
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[rgba(179,14,20,0.14)] bg-[#0a0a0a] px-4 py-3">
        <p className="text-sm text-zinc-300">{allCves.length} CVEs loaded · {pageCves.length} on this page. Patch plans use this page only.</p>
        <button type="button" className={styles.button} disabled={pageCves.length < 2 || pageCves.length > 100} onClick={() => setConsolidating([...pageCves])}>Build patch plan for this page</button>
        {pageCves.length > 100 && <p className={styles.resultNote}>This page contains more than 100 distinct CVEs. Use a query with one CVE per row to build a patch plan.</p>}
      </div>
    )}
    <div ref={tableScroll} role="region" aria-label="Scrollable query results" tabIndex={0} className={styles.tableScroll}>
      <table className={styles.table}>
        <caption className="sr-only">Dashboard query results</caption>
        <thead><tr>{result.columns.map((column) => <th key={column.name} scope="col" className={numericColumn(column.type) ? styles.number : undefined}>{columnLabel(column.name)}</th>)}</tr></thead>
        <tbody>{pageRows.map((row, index) => <tr key={page * pageSize + index}>
          {row.map((value, position) => <td key={position} className={numericColumn(result.columns[position].type) ? styles.number : undefined}>
            {typeof value === "string" && /\bCVE-\d{4}-\d{4,19}\b/i.test(value) ? <CveText text={value} onSelect={cve => setSelected({ cve, row })} /> :
              position === devicesIndex && typeof value === "number" ? <span className={styles.deviceValue}><span className={styles.miniTrack} aria-hidden="true"><span style={{ width: `${value / maxDevices * 100}%` }} /></span>{formatResultValue(value, result.columns[position].name)}</span> : cell(value, result.columns[position].name)}
          </td>)}
        </tr>)}</tbody>
      </table>
    </div>
    <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
      <p className={styles.resultNote} aria-live="polite">{result.rows.length ? `Rows ${page * pageSize + 1}–${Math.min((page + 1) * pageSize, result.rows.length)} of ${result.rows.length} loaded${hasCves ? " · Select a CVE for details" : ""}` : "The query returned no rows."}</p>
      {pageCount > 1 && <nav aria-label="Table pages" className="flex items-center gap-2">
        <button type="button" className={styles.button} disabled={page === 0} onClick={() => changePage(page - 1)}>Previous</button>
        <span className={styles.resultNote}>Page {page + 1} of {pageCount}</span>
        <button type="button" className={styles.button} disabled={page === pageCount - 1} onClick={() => changePage(page + 1)}>Next</button>
      </nav>}
    </div>
    {result.truncated && <p className="mt-3 text-sm text-amber-300">Only the first {result.rows.length} result rows were loaded. These pages do not include the full query result; narrow or aggregate the query.</p>}
    {details}
    {consolidationPanel}
  </div>;
}
