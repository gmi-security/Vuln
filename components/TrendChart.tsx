"use client";

import React, { useId, useMemo, useState } from "react";
import { severityBarColor } from "@/lib/format";
import type { Severity } from "@/lib/types";

// One row of /api/history (and of the report payload's `trend`).
export type TrendSnapshot = {
  ts: string;
  companyId: string | null;
  totalOpen: number;
  severityCounts: Record<Severity, number>;
  exploitableOpen: number;
  kevOpen: number;
  composite: number;
  exposureScore: number;
  resolvedTotal: number;
  mttrDays: number | null;
};

// Chart geometry (viewBox units — the SVG scales to its container width).
const W = 720;
const H = 230;
const PAD_L = 46;
const PAD_R = 14;
const PAD_T = 14;
const PAD_B = 28;

const THEMES = {
  dark: {
    text: "#71717a",
    grid: "rgba(255,255,255,0.07)",
    axis: "rgba(255,255,255,0.14)",
    total: "#d4d4d8",
    areaFrom: "rgba(179,14,20,0.30)",
    areaTo: "rgba(179,14,20,0.02)",
    guide: "rgba(255,255,255,0.22)",
    dotRing: "#050505",
    tooltipBg: "#0a0a0a",
    tooltipBorder: "#27272a",
    tooltipText: "#fafafa",
    tooltipMuted: "#71717a",
    legendText: "#a1a1aa",
  },
  light: {
    text: "#64748b",
    grid: "#e2e8f0",
    axis: "#cbd5e1",
    total: "#0f172a",
    areaFrom: "rgba(179,14,20,0.14)",
    areaTo: "rgba(179,14,20,0.01)",
    guide: "#94a3b8",
    dotRing: "#ffffff",
    tooltipBg: "#ffffff",
    tooltipBorder: "#e2e8f0",
    tooltipText: "#0f172a",
    tooltipMuted: "#64748b",
    legendText: "#475569",
  },
} as const;

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

// 1/2/5 × 10^k step so y ticks land on round numbers.
function niceStep(rough: number): number {
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(rough, 1))));
  const norm = rough / mag;
  if (norm <= 1) return mag;
  if (norm <= 2) return 2 * mag;
  if (norm <= 5) return 5 * mag;
  return 10 * mag;
}

export default function TrendChart({
  snapshots,
  theme = "dark",
}: {
  snapshots: TrendSnapshot[];
  theme?: "dark" | "light";
}) {
  const t = THEMES[theme];
  const gradientId = useId();
  const [hover, setHover] = useState<number | null>(null);

  const rows = useMemo(
    () =>
      [...snapshots].sort(
        (a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime(),
      ),
    [snapshots],
  );

  const n = rows.length;

  const { yMax, ticks } = useMemo(() => {
    const dataMax = Math.max(1, ...rows.map((r) => r.totalOpen || 0));
    const step = niceStep(dataMax / 3);
    const top = Math.max(step, Math.ceil(dataMax / step) * step);
    const tickValues: number[] = [];
    for (let v = 0; v <= top; v += step) tickValues.push(v);
    return { yMax: top, ticks: tickValues };
  }, [rows]);

  if (n < 2) {
    return (
      <div
        className="flex h-48 items-center justify-center rounded-2xl border border-dashed px-6 text-center text-sm"
        style={{
          borderColor: theme === "dark" ? "#27272a" : "#e2e8f0",
          color: t.text,
        }}
      >
        Trend data starts accumulating after the first daily snapshot.
      </div>
    );
  }

  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;
  const x = (i: number) => PAD_L + (i / (n - 1)) * innerW;
  const y = (v: number) => PAD_T + innerH - (Math.max(0, v) / yMax) * innerH;

  const totalPts = rows.map((r, i) => `${x(i).toFixed(2)},${y(r.totalOpen).toFixed(2)}`);
  const critPts = rows.map(
    (r, i) =>
      `${x(i).toFixed(2)},${y(r.severityCounts?.Critical ?? 0).toFixed(2)}`,
  );
  const areaPath = `M${totalPts.join(" L")} L${x(n - 1).toFixed(2)},${(PAD_T + innerH).toFixed(2)} L${x(0).toFixed(2)},${(PAD_T + innerH).toFixed(2)} Z`;

  const xLabelIdx = [0, Math.floor((n - 1) / 2), n - 1];

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const fx = ((e.clientX - rect.left) / rect.width) * W;
    const frac = (fx - PAD_L) / innerW;
    const idx = Math.round(frac * (n - 1));
    setHover(Math.min(n - 1, Math.max(0, idx)));
  }

  const hovered = hover !== null ? rows[hover] : null;
  const hoverPct = hover !== null ? (x(hover) / W) * 100 : 0;
  const flip = hoverPct > 72;

  return (
    <div>
      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="block w-full"
          role="img"
          aria-label="Open findings trend, last 90 days"
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={t.areaFrom} />
              <stop offset="100%" stopColor={t.areaTo} />
            </linearGradient>
          </defs>

          {/* y gridlines + labels */}
          {ticks.map((v) => (
            <g key={v}>
              <line
                x1={PAD_L}
                x2={W - PAD_R}
                y1={y(v)}
                y2={y(v)}
                stroke={v === 0 ? t.axis : t.grid}
                strokeWidth={1}
              />
              <text
                x={PAD_L - 8}
                y={y(v) + 3.5}
                textAnchor="end"
                fontSize={11}
                fill={t.text}
              >
                {v}
              </text>
            </g>
          ))}

          {/* x date labels: first / middle / last */}
          {xLabelIdx.map((i, k) => (
            <text
              key={`${i}-${k}`}
              x={x(i)}
              y={H - 8}
              textAnchor={k === 0 ? "start" : k === 2 ? "end" : "middle"}
              fontSize={11}
              fill={t.text}
            >
              {shortDate(rows[i].ts)}
            </text>
          ))}

          {/* total open: area + line */}
          <path d={areaPath} fill={`url(#${gradientId})`} />
          <polyline
            points={totalPts.join(" ")}
            fill="none"
            stroke={t.total}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />

          {/* critical overlay line */}
          <polyline
            points={critPts.join(" ")}
            fill="none"
            stroke={severityBarColor.Critical}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />

          {/* hover guide + markers */}
          {hover !== null && hovered ? (
            <g>
              <line
                x1={x(hover)}
                x2={x(hover)}
                y1={PAD_T}
                y2={PAD_T + innerH}
                stroke={t.guide}
                strokeWidth={1}
                strokeDasharray="3 3"
              />
              <circle
                cx={x(hover)}
                cy={y(hovered.totalOpen)}
                r={4}
                fill={t.total}
                stroke={t.dotRing}
                strokeWidth={2}
              />
              <circle
                cx={x(hover)}
                cy={y(hovered.severityCounts?.Critical ?? 0)}
                r={4}
                fill={severityBarColor.Critical}
                stroke={t.dotRing}
                strokeWidth={2}
              />
            </g>
          ) : null}
        </svg>

        {/* tooltip readout */}
        {hovered ? (
          <div
            className="pointer-events-none absolute top-1 z-10 rounded-xl border px-3 py-2 text-xs shadow-lg"
            style={{
              left: `${hoverPct}%`,
              transform: flip ? "translateX(calc(-100% - 10px))" : "translateX(10px)",
              background: t.tooltipBg,
              borderColor: t.tooltipBorder,
              color: t.tooltipText,
            }}
          >
            <div style={{ color: t.tooltipMuted }}>{shortDate(hovered.ts)}</div>
            <div className="mt-1 flex items-center gap-2 whitespace-nowrap">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: t.total }}
              />
              Open {hovered.totalOpen}
            </div>
            <div className="mt-0.5 flex items-center gap-2 whitespace-nowrap">
              <span
                className="inline-block h-2 w-2 rounded-full"
                style={{ background: severityBarColor.Critical }}
              />
              Critical {hovered.severityCounts?.Critical ?? 0}
            </div>
          </div>
        ) : null}
      </div>

      {/* legend */}
      <div
        className="mt-2 flex items-center gap-5 text-xs"
        style={{ color: t.legendText }}
      >
        <span className="flex items-center gap-2">
          <span
            className="inline-block h-[3px] w-5 rounded-full"
            style={{ background: t.total }}
          />
          Open findings
        </span>
        <span className="flex items-center gap-2">
          <span
            className="inline-block h-[3px] w-5 rounded-full"
            style={{ background: severityBarColor.Critical }}
          />
          Critical open
        </span>
      </div>
    </div>
  );
}
