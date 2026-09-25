"use client";

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { chartData, columnLabel, type QueryDefinition, type QueryResult } from "@/lib/elastic-dashboard";

import CveText, { cveIdentifier } from "@/components/CveText";

const colors = ["#f87171", "#fbbf24", "#38bdf8", "#a78bfa", "#34d399", "#fb923c", "#f472b6", "#a3e635"];
const number = (value: number) => value.toLocaleString("en-US", { maximumFractionDigits: 2 });
const short = (text: string, length = 24) => text.length > length ? `${text.slice(0, length - 1)}…` : text;

export default function ElasticResultChart({ result, definition, onCveSelect }: {
  result: QueryResult; definition: Pick<QueryDefinition, "display" | "chart">; onCveSelect?: (cve: string) => void;
}) {
  const titleId = useId();
  const container = useRef<HTMLDivElement>(null);
  const [plotWidth, setPlotWidth] = useState(760);
  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const resize = () => setPlotWidth(Math.max(560, Math.floor(element.clientWidth)));
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    return () => observer.disconnect();
  }, [result, definition.display]);
  let data: ReturnType<typeof chartData>;
  try { data = chartData(result, definition); }
  catch (error) { return <p role="alert" className="py-4 text-sm text-amber-300">{error instanceof Error ? error.message : "Unable to display this chart."}</p>; }
  const { points, category, value, scale } = data;
  const chartRole = onCveSelect && points.some(point => cveIdentifier(point.label)) ? "group" : "img";
  function cveAction(label: string) {
    const cve = cveIdentifier(label);
    if (!cve || !onCveSelect) return {};
    const select = () => onCveSelect(cve);
    return { role: "button" as const, tabIndex: 0, "aria-label": `View ${cve} details`, style: { cursor: "pointer" }, onClick: select,
      onKeyDown: (event: KeyboardEvent<SVGElement>) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); } } };
  }
  const values = points.flatMap((point) => point.value === null ? [] : [point.value]);
  const format = (n: number) => `${number(n)}${/(?:_pct|_percent|percentage)$/i.test(value) ? "%" : ""}`;
  const description = `${columnLabel(value)} by ${columnLabel(category)}`;
  const minimum = Math.min(0, ...values), maximum = Math.max(0, ...values);
  // Normalize first to keep the scale finite even with very large signed values.
  const unit = Math.max(Math.abs(minimum), Math.abs(maximum), 1);
  const low = minimum / unit, high = maximum / unit || 1;
  const fraction = (n: number) => (n / unit - low) / (high - low);
  const total = values.reduce((sum, n) => sum + n, 0);
  const empty = !points.length || !values.length;
  const subtitle = <p className="mb-3 text-sm text-zinc-400">{description}</p>;

  let chart;
  if (empty) chart = <p className="py-10 text-center text-zinc-400">{points.length ? "No numeric values to plot. Null values are missing data." : "The query returned no rows."}</p>;
  else if (definition.display === "doughnut") {
    // Compute proportions using scaled values to avoid sum overflow.
    const scaledTotal = values.reduce((sum, n) => sum + n / unit, 0);
    let offset = 0;
    chart = scaledTotal === 0 ? <p className="py-10 text-center text-zinc-400">All values are zero. No proportions to display.</p> :
      <div className="flex flex-wrap items-center gap-8">
        <svg viewBox="0 0 240 240" className="w-60 max-w-full shrink-0" role={chartRole} aria-labelledby={titleId}>
          <title id={titleId}>{description}</title>
          <circle cx="120" cy="120" r="82" fill="none" stroke="#27272a" strokeWidth="34" />
          {points.map((point, index) => {
            const share = (point.value ?? 0) / unit / scaledTotal;
            const start = offset; offset += share;
            return share > 0 ? <circle key={index} cx="120" cy="120" r="82" fill="none" stroke={colors[index % colors.length]}
              strokeWidth="34" pathLength="100" strokeDasharray={`${share * 100} ${100 - share * 100}`}
              strokeDashoffset={-start * 100} transform="rotate(-90 120 120)" tabIndex={0} {...cveAction(point.label)}>
              <title>{`${point.label}: ${format(point.value!)} (${number(share * 100)}%)`}</title>
            </circle> : null;
          })}
          <text x="120" y="115" textAnchor="middle" fill="#a1a1aa" fontSize="13">Total</text>
          <text x="120" y="142" textAnchor="middle" fill="#fafafa" fontSize="22">{Number.isFinite(total) ? short(format(total), 13) : "See values"}</text>
        </svg>
        <ul className="max-h-80 min-w-0 flex-1 space-y-2 overflow-y-auto text-sm">
          {points.map((point, index) => <li key={index} className="flex items-start gap-3">
            <span className="mt-1 h-3 w-3 shrink-0 rounded-sm" style={{ background: colors[index % colors.length] }} />
            <span className="min-w-0 flex-1 break-words text-zinc-300"><CveText text={point.label} onSelect={onCveSelect} /></span>
            <span className="shrink-0 tabular-nums text-white">{point.value === null ? "No data" : `${format(point.value)} · ${number(point.value / unit / scaledTotal * 100)}%`}</span>
          </li>)}
        </ul>
      </div>;
  } else if (definition.display === "bar") {
    const width = plotWidth, left = 195, plot = width - left - 115, zero = left + fraction(0) * plot;
    chart = <div className="max-h-[520px] overflow-auto">
      <svg viewBox={`0 0 ${width} ${points.length * 36 + 45}`} width={width} height={points.length * 36 + 45} className="block max-w-none" role={chartRole} aria-labelledby={titleId}>
        <title id={titleId}>{`${description}. Bars start at zero.`}</title>
        <line x1={zero} x2={zero} y1="5" y2={points.length * 36} stroke="#71717a" />
        {points.map((point, index) => {
          const x = point.value === null ? zero : left + fraction(point.value) * plot;
          const y = index * 36 + 5;
          return <g key={index} tabIndex={0} {...cveAction(point.label)}>
            <title>{`${point.label}: ${point.value === null ? "No data" : format(point.value)}`}</title>
            <text x={left - 12} y={y + 18} textAnchor="end" fill="#d4d4d8" fontSize="13">{short(point.label)}</text>
            {point.value !== null && <rect x={Math.min(x, zero)} y={y} width={Math.abs(x - zero)} height="25" rx="3" fill={colors[index % colors.length]} />}
            <text x={width - 100} y={y + 18} fill="#fafafa" fontSize="13">{point.value === null ? "No data" : short(format(point.value), 13)}</text>
          </g>;
        })}
        <text x={zero} y={points.length * 36 + 22} textAnchor="middle" fill="#a1a1aa" fontSize="12">0</text>
      </svg>
    </div>;
  } else {
    const left = 100, top = 20, width = plotWidth - left - 40, height = 230;
    const firstX = points[0].x, lastX = points[points.length - 1].x;
    const x = (index: number) => left + (points.length === 1 ? 0.5 : scale === "category" || lastX === firstX ? index / (points.length - 1) : (points[index].x - firstX) / (lastX - firstX)) * width;
    const y = (n: number) => top + height * (1 - fraction(n));
    const tickLabel = (index: number) => {
      const label = points[index].label;
      return scale === "time" && /^\d{4}-\d{2}-\d{2}T/.test(label)
        ? label.replace("T", " ").slice(0, /T00:00:00/.test(label) ? 10 : 16)
        : short(label, 22);
    };
    const ticks = new Set([0]);
    const last = points.length - 1;
    if (last > 0) ticks.add(last);
    let previousX = x(0), previousRight = x(0) + tickLabel(0).length * 7;
    const finalLeft = x(last) - tickLabel(last).length * 7;
    for (let index = 1; index < last; index++) {
      const half = tickLabel(index).length * 3.5;
      if (x(index) - half >= previousRight + 12 && x(index) + half <= finalLeft - 12 && x(index) - previousX >= Math.max(120, width / 5)) {
        ticks.add(index); previousX = x(index); previousRight = x(index) + half;
      }
    }
    let penDown = false;
    const path = points.map((point, index) => {
      if (point.value === null) { penDown = false; return ""; }
      const command = penDown ? "L" : "M"; penDown = true;
      return `${command}${x(index)},${y(point.value)}`;
    }).join(" ");
    chart = <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${plotWidth} 335`} width={plotWidth} height="335" className="block max-w-none" role={chartRole} aria-labelledby={titleId}>
        <title id={titleId}>{`${description}. Null values leave gaps in the line.`}</title>
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => <g key={tick}>
          <line x1={left} x2={left + width} y1={top + height * tick} y2={top + height * tick} stroke="#27272a" />
          <text x={left - 10} y={top + height * tick + 4} textAnchor="end" fill="#d4d4d8" fontSize="12">{short(format((high - tick * (high - low)) * unit), 12)}</text>
        </g>)}
        <path d={path} fill="none" stroke="#38bdf8" strokeWidth="3" />
        {points.map((point, index) => <g key={index} {...cveAction(point.label)}>
          {point.value !== null && <circle cx={x(index)} cy={y(point.value)} r="4" fill="#38bdf8" stroke="#09090b" tabIndex={onCveSelect && cveIdentifier(point.label) ? -1 : 0}>
            <title>{`${point.label}: ${format(point.value)}`}</title>
          </circle>}
          {ticks.has(index) &&
            <text x={x(index)} y="275" textAnchor={index === 0 ? "start" : index === points.length - 1 ? "end" : "middle"} fill="#d4d4d8" fontSize="12">
              {tickLabel(index)}
            </text>}
        </g>)}
        <text x={left + width / 2} y="320" textAnchor="middle" fill="#d4d4d8" fontSize="13">{columnLabel(category)}{scale === "time" ? " (UTC)" : ""}</text>
      </svg>
    </div>;
  }

  return <div ref={container} className="min-w-0">{subtitle}{chart}
    {result.truncated && <p className="mt-3 text-sm text-amber-300">Partial chart: only the first 100 result rows are shown. Narrow or aggregate the query to include the full result.</p>}
    <details className="mt-4 text-sm text-zinc-300">
      <summary className="cursor-pointer">View chart data</summary>
      {definition.display === "line" && <p className="mt-2">{scale === "category" ? "Categories follow query order. Use SORT in ES|QL to set the order." : "The horizontal axis is sorted and spaced by value."}</p>}
      <div className="mt-3 max-h-80 overflow-auto"><table className="w-full text-left">
        <caption className="sr-only">{description}</caption>
        <thead><tr><th scope="col" className="p-2">{columnLabel(category)}</th><th scope="col" className="p-2">{columnLabel(value)}</th></tr></thead>
        <tbody>{points.map((point, index) => <tr key={index} className="border-t border-zinc-800"><td className="break-words p-2"><CveText text={point.label} onSelect={onCveSelect} /></td><td className="p-2">{point.value === null ? "No data" : format(point.value)}</td></tr>)}</tbody>
      </table></div>
    </details>
  </div>;
}
