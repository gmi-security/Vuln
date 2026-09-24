"use client";

import { useEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import ElasticResultChart from "@/components/ElasticResultChart";
import { canShowMetrics, columnLabel, isChartDisplay, numericColumn, type QueryDefinition, type QueryResult } from "@/lib/elastic-dashboard";
import { severityBarColor, severityClass } from "@/lib/format";
import type { Severity } from "@/lib/types";
import styles from "./QueryDashboard.module.css";

function severity(value: string): Severity | undefined {
  return Object.keys(severityBarColor).find((key) => key.toLowerCase() === value.toLowerCase()) as Severity | undefined;
}

export function formatResultValue(value: string | number | boolean | null, column: string): string {
  if (value === null) return "—";
  if (typeof value === "number") {
    const formatted = value.toLocaleString("en-US", { maximumFractionDigits: 2 });
    return /(?:_pct|_percent|percentage)$/i.test(column) ? `${formatted}%` : formatted;
  }
  if (column === "cisa_kev" && typeof value === "boolean") return value ? "Listed" : "Not listed";
  return String(value);
}

export default function QueryDashboardResults({ result, display, chart }: {
  result: QueryResult; display: QueryDefinition["display"]; chart?: QueryDefinition["chart"];
}) {
  const [selected, setSelected] = useState<QueryResult["rows"][number] | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => { if (selected) dialog.current?.showModal(); }, [selected]);

  if (isChartDisplay(display)) return <ElasticResultChart result={result} definition={{ display, chart }} />;
  if (display !== "table" && canShowMetrics(result)) {
    const severityMetrics = result.columns.every((column) => severity(column.name) || /^(none|unknown)$/i.test(column.name));
    const total = severityMetrics ? result.rows[0].reduce<number>((sum, value) => sum + (typeof value === "number" ? value : 0), 0) : 0;
    return <div className={styles.metrics}>
      {result.columns.map((column, index) => {
        const level = severity(column.name), value = result.rows[0][index];
        const share = total > 0 && typeof value === "number" ? value / total * 100 : 0;
        const color = level ? severityBarColor[level] : "#b30e14";
        return <div key={column.name} className={styles.metric}>
          <div className={styles.metricLabel}>{level && <span className={styles.dot} style={{ background: color }} />}{columnLabel(column.name)}</div>
          <div className={styles.metricValue}>{formatResultValue(value, column.name)}</div>
          {severityMetrics && <><div className={styles.track} aria-hidden="true"><span style={{ width: `${share}%`, background: color }} /></div>
            <div className={styles.metricNote}>{total > 0 ? `${share.toFixed(1)}% of returned findings` : "No findings"}</div></>}
        </div>;
      })}
    </div>;
  }
  const cveIndex = result.columns.findIndex((column) => /^(cve|vulnerability\.id)$/i.test(column.name));
  const devicesIndex = result.columns.findIndex((column) => column.name === "affected_devices");
  const maxDevices = Math.max(1, ...result.rows.map((row) => typeof row[devicesIndex] === "number" ? row[devicesIndex] as number : 0));
  function cell(value: QueryResult["rows"][number][number], name: string) {
    const level = /severity/i.test(name) && typeof value === "string" ? severity(value) : undefined;
    if (level) return <span className={`${styles.badge} ${severityClass[level]}`}>{level}</span>;
    if (name === "cisa_kev" && value === true) return <span className="text-[#ff4d57]">Listed</span>;
    return formatResultValue(value, name);
  }
  return <div>
    <div role="region" aria-label="Scrollable query results" tabIndex={0} className={styles.tableScroll}>
      <table className={styles.table}>
        <caption className="sr-only">Dashboard query results</caption>
        <thead><tr>{result.columns.map((column) => <th key={column.name} scope="col" className={numericColumn(column.type) ? styles.number : undefined}>{columnLabel(column.name)}</th>)}</tr></thead>
        <tbody>{result.rows.map((row, index) => <tr key={index}>
          {row.map((value, position) => <td key={position} className={numericColumn(result.columns[position].type) ? styles.number : undefined}>
            {position === cveIndex && typeof value === "string" ? <button type="button" className={styles.cveButton} onClick={() => setSelected(row)} aria-label={`View ${value} details`}>{value}</button> :
              position === devicesIndex && typeof value === "number" ? <span className={styles.deviceValue}><span className={styles.miniTrack} aria-hidden="true"><span style={{ width: `${value / maxDevices * 100}%` }} /></span>{formatResultValue(value, result.columns[position].name)}</span> : cell(value, result.columns[position].name)}
          </td>)}
        </tr>)}</tbody>
      </table>
    </div>
    <p className={styles.resultNote}>{result.rows.length ? `${result.rows.length} rows · Scroll inside the table${cveIndex >= 0 ? " · Select a CVE for details" : ""}` : "The query returned no rows."}</p>
    {result.truncated && <p className="mt-3 text-sm text-amber-300">Showing the first 100 rows. Narrow or aggregate the query to show the full result.</p>}
    <dialog ref={dialog} className={styles.detail} aria-labelledby={titleId} onClose={() => setSelected(null)} onClick={(event) => { if (event.target === event.currentTarget) dialog.current?.close(); }}>
      <div className={styles.detailBody}>
        <div className={styles.detailTop}><span>CVE details</span><button type="button" className={styles.button} onClick={() => dialog.current?.close()}><X size={15} />Close</button></div>
        <h2 id={titleId}>{selected && cveIndex >= 0 ? String(selected[cveIndex]) : "CVE details"}</h2>
        <p className={styles.resultNote}>Snapshot of the result selected from this tile.</p>
        <dl className={styles.detailFields}>{selected && result.columns.map((column, index) => index !== cveIndex && <div key={column.name}><dt>{columnLabel(column.name)}</dt><dd>{cell(selected[index], column.name)}</dd></div>)}</dl>
      </div>
    </dialog>
  </div>;
}
