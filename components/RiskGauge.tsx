"use client";

import React from "react";

// Kenna-style circular risk gauge: a ring of tick marks (not a smooth arc)
// that fill clockwise from 12 o'clock as the score rises, with the score
// itself as a big number in the center. Visually modeled on Kenna
// Security's "Current Score" ring, built from plain SVG (no chart library)
// so it stays in our own dark/red theme instead of picking up a generic
// chart palette.
function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

const TICK_COUNT = 64;
const TICK_INNER = 5; // half-length of each tick, px, inward from the ring radius
const TICK_OUTER = 5; // half-length of each tick, px, outward from the ring radius

export default function RiskGauge({
  score,
  max = 100,
  color,
  trackColor = "#1c1c1c",
  size = 176,
  label,
  sublabel,
}: {
  score: number;
  max?: number;
  color: string;
  trackColor?: string;
  size?: number;
  label?: string;
  sublabel?: string;
}) {
  const pct = Math.max(0, Math.min(1, score / max));
  const filledTicks = Math.round(pct * TICK_COUNT);
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 14;

  const ticks = Array.from({ length: TICK_COUNT }, (_, i) => {
    const angle = (i / TICK_COUNT) * 360;
    const p1 = polarToCartesian(cx, cy, r - TICK_INNER, angle);
    const p2 = polarToCartesian(cx, cy, r + TICK_OUTER, angle);
    return { i, p1, p2, filled: i < filledTicks };
  });

  return (
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`${label ?? "Score"}: ${Math.round(score)} of ${max}`}
    >
      <svg width={size} height={size} className="block">
        {ticks.map((t) => (
          <line
            key={t.i}
            x1={t.p1.x}
            y1={t.p1.y}
            x2={t.p2.x}
            y2={t.p2.y}
            stroke={t.filled ? color : trackColor}
            strokeWidth={2.25}
            strokeLinecap="round"
            style={{ transition: "stroke 0.5s ease" }}
          />
        ))}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="text-4xl font-bold tabular-nums"
          style={{ color }}
        >
          {Math.round(score)}
        </span>
        {label ? (
          <span className="mt-1 text-[11px] uppercase tracking-[0.2em] text-zinc-500">
            {label}
          </span>
        ) : null}
        {sublabel ? (
          <span className="mt-0.5 text-[11px] text-zinc-600">{sublabel}</span>
        ) : null}
      </div>
    </div>
  );
}
