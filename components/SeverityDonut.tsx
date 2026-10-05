"use client";

import React from "react";
import { severityBarColor } from "@/lib/format";
import type { Severity } from "@/lib/types";
import { useCountUp } from "@/lib/useCountUp";

const SIZE = 168;
const STROKE = 20;
const R = (SIZE - STROKE) / 2;
const CIRC = 2 * Math.PI * R;

// Radial donut replacing a plain horizontal-bar severity breakdown --
// each severity gets an arc sized to its share of total open findings,
// drawn clockwise from 12 o'clock with a small gap between segments, total
// count centered. Built with plain SVG stroke-dasharray math (no chart
// library) so it matches RiskGauge's technique and our theme exactly.
export default function SeverityDonut({
  counts,
  order,
}: {
  counts: Record<Severity, number>;
  order: Severity[];
}) {
  const total = order.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  const animatedTotal = useCountUp(total);
  const gap = total > 0 ? 6 : 0; // px of track left blank between segments

  let cumulative = 0;
  const segments = order
    .map((severity) => {
      const count = counts[severity] ?? 0;
      if (count === 0 || total === 0) return null;
      const length = Math.max(0, (count / total) * CIRC - gap);
      const offset = -(cumulative / total) * CIRC;
      cumulative += count;
      return { severity, count, length, offset, color: severityBarColor[severity] };
    })
    .filter((s): s is NonNullable<typeof s> => s !== null);

  return (
    <div className="flex items-center gap-6">
      <div className="relative shrink-0" style={{ width: SIZE, height: SIZE }}>
        <svg width={SIZE} height={SIZE} className="-rotate-90">
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={R}
            fill="none"
            stroke="#141414"
            strokeWidth={STROKE}
          />
          {segments.map((s) => (
            <circle
              key={s.severity}
              cx={SIZE / 2}
              cy={SIZE / 2}
              r={R}
              fill="none"
              stroke={s.color}
              strokeWidth={STROKE}
              strokeLinecap="round"
              strokeDasharray={`${s.length} ${CIRC - s.length}`}
              strokeDashoffset={s.offset}
              style={{
                filter: `drop-shadow(0 0 5px ${s.color}88)`,
                transition: "stroke-dasharray 0.6s ease, stroke-dashoffset 0.6s ease",
              }}
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold tabular-nums text-white">
            {Math.round(animatedTotal).toLocaleString()}
          </span>
          <span className="mt-0.5 text-[10px] uppercase tracking-[0.2em] text-zinc-500">
            Open
          </span>
        </div>
      </div>
      <div className="flex-1 space-y-2">
        {order.map((severity) => {
          const count = counts[severity] ?? 0;
          return (
            <div key={severity} className="flex items-center gap-2.5 text-sm">
              <span
                className="h-2.5 w-2.5 shrink-0 rounded-full"
                style={{ background: severityBarColor[severity], boxShadow: `0 0 6px ${severityBarColor[severity]}aa` }}
              />
              <span className="flex-1 text-zinc-400">{severity}</span>
              <span className="font-semibold tabular-nums text-white">{count.toLocaleString()}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
