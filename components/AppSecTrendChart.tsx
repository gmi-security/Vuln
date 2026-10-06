"use client";

import React, { useId, useMemo, useState } from "react";
import type { AppSecScanHistory } from "@/lib/elastic-appsec";

// Chart geometry (viewBox units -- the SVG scales to its container width).
const W = 720;
const H = 220;
const PAD_L = 40;
const PAD_R = 14;
const PAD_T = 14;
const PAD_B = 28;

const CRITICAL = "#b30e14";
const HIGH = "#f97316";
const RESOLVED = "#10b981";
const AREA_FROM = "rgba(179,14,20,0.22)";
const AREA_TO = "rgba(179,14,20,0.02)";

function shortDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

// 1/2/5 x 10^k step so y ticks land on round numbers.
function niceStep(rough: number): number {
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(rough, 1))));
  const norm = rough / mag;
  if (norm <= 1) return mag;
  if (norm <= 2) return 2 * mag;
  if (norm <= 5) return 5 * mag;
  return 10 * mag;
}

// AppSecScanHistory arrives newest-first (SORT @timestamp DESC in the ES|QL
// query); this chart reads left-to-right as time passing, so it needs the
// chronological order flipped back before plotting.
export default function AppSecTrendChart({ scans }: { scans: AppSecScanHistory[] }) {
  const gradientId = useId();
  const [hover, setHover] = useState<number | null>(null);

  const rows = useMemo(() => [...scans].reverse(), [scans]);
  const n = rows.length;

  const { yMax, ticks } = useMemo(() => {
    const dataMax = Math.max(1, ...rows.map((r) => Math.max(r.critical + r.high, r.resolved)));
    const step = niceStep(dataMax / 3);
    const top = Math.max(step, Math.ceil(dataMax / step) * step);
    const tickValues: number[] = [];
    for (let v = 0; v <= top; v += step) tickValues.push(v);
    return { yMax: top, ticks: tickValues };
  }, [rows]);

  if (n < 2) {
    return (
      <div className="flex h-44 items-center justify-center rounded-2xl border border-dashed border-zinc-800 px-6 text-center text-sm text-zinc-500">
        Trend appears once this repository has at least two completed scans.
      </div>
    );
  }

  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;
  const x = (i: number) => PAD_L + (i / (n - 1)) * innerW;
  const y = (v: number) => PAD_T + innerH - (Math.max(0, v) / yMax) * innerH;
  const barW = Math.min(18, (innerW / n) * 0.5);

  const criticalPts = rows.map((r, i) => `${x(i).toFixed(2)},${y(r.critical).toFixed(2)}`);
  const combinedPts = rows.map((r, i) => `${x(i).toFixed(2)},${y(r.critical + r.high).toFixed(2)}`);
  const areaPath = `M${combinedPts.join(" L")} L${x(n - 1).toFixed(2)},${(PAD_T + innerH).toFixed(2)} L${x(0).toFixed(2)},${(PAD_T + innerH).toFixed(2)} Z`;

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
          aria-label="Critical and high findings, and fixes resolved, across scans"
          onMouseMove={onMove}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={AREA_FROM} />
              <stop offset="100%" stopColor={AREA_TO} />
            </linearGradient>
          </defs>

          {ticks.map((v) => (
            <g key={v}>
              <line
                x1={PAD_L}
                x2={W - PAD_R}
                y1={y(v)}
                y2={y(v)}
                stroke={v === 0 ? "rgba(255,255,255,0.14)" : "rgba(255,255,255,0.07)"}
                strokeWidth={1}
              />
              <text x={PAD_L - 8} y={y(v) + 3.5} textAnchor="end" fontSize={11} fill="#71717a">
                {v}
              </text>
            </g>
          ))}

          {xLabelIdx.map((i, k) => (
            <text
              key={`${i}-${k}`}
              x={x(i)}
              y={H - 8}
              textAnchor={k === 0 ? "start" : k === 2 ? "end" : "middle"}
              fontSize={11}
              fill="#71717a"
            >
              {shortDate(rows[i].completedAt)}
            </text>
          ))}

          {/* fixes landed per scan, as bars behind the criticality line */}
          {rows.map((r, i) =>
            r.resolved > 0 ? (
              <rect
                key={`resolved-${i}`}
                x={x(i) - barW / 2}
                y={y(r.resolved)}
                width={barW}
                height={PAD_T + innerH - y(r.resolved)}
                rx={2}
                fill={RESOLVED}
                opacity={0.35}
              />
            ) : null,
          )}

          {/* critical + high: area + line -- the criticality trend */}
          <path d={areaPath} fill={`url(#${gradientId})`} />
          <polyline
            points={combinedPts.join(" ")}
            fill="none"
            stroke={HIGH}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          <polyline
            points={criticalPts.join(" ")}
            fill="none"
            stroke={CRITICAL}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
          />

          {hover !== null && hovered ? (
            <g>
              <line
                x1={x(hover)}
                x2={x(hover)}
                y1={PAD_T}
                y2={PAD_T + innerH}
                stroke="rgba(255,255,255,0.22)"
                strokeWidth={1}
                strokeDasharray="3 3"
              />
              <circle cx={x(hover)} cy={y(hovered.critical + hovered.high)} r={4} fill={HIGH} stroke="#050505" strokeWidth={2} />
              <circle cx={x(hover)} cy={y(hovered.critical)} r={4} fill={CRITICAL} stroke="#050505" strokeWidth={2} />
            </g>
          ) : null}
        </svg>

        {hovered ? (
          <div
            className="pointer-events-none absolute top-1 z-10 rounded-xl border px-3 py-2 text-xs shadow-lg"
            style={{
              left: `${hoverPct}%`,
              transform: flip ? "translateX(calc(-100% - 10px))" : "translateX(10px)",
              background: "#0a0a0a",
              borderColor: "#27272a",
              color: "#fafafa",
            }}
          >
            <div style={{ color: "#71717a" }}>{shortDate(hovered.completedAt)}</div>
            <div className="mt-1 flex items-center gap-2 whitespace-nowrap">
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: CRITICAL }} />
              Critical {hovered.critical}
            </div>
            <div className="mt-0.5 flex items-center gap-2 whitespace-nowrap">
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: HIGH }} />
              High {hovered.high}
            </div>
            <div className="mt-0.5 flex items-center gap-2 whitespace-nowrap">
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: RESOLVED }} />
              Fixed {hovered.resolved}
            </div>
          </div>
        ) : null}
      </div>

      <div className="mt-2 flex items-center gap-5 text-xs text-zinc-400">
        <span className="flex items-center gap-2">
          <span className="inline-block h-[3px] w-5 rounded-full" style={{ background: HIGH }} />
          Critical + High open
        </span>
        <span className="flex items-center gap-2">
          <span className="inline-block h-[3px] w-5 rounded-full" style={{ background: CRITICAL }} />
          Critical open
        </span>
        <span className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-sm" style={{ background: RESOLVED, opacity: 0.6 }} />
          Fixed per scan
        </span>
      </div>
    </div>
  );
}
