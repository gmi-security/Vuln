"use client";

import React from "react";
import { useCountUp } from "@/lib/useCountUp";

// Kenna-style circular risk gauge, pushed further: a ring of tick marks that
// sweep in clockwise on mount (like a radar lock-on) instead of appearing
// static, with a soft color-matched glow and a slow ambient pulse when the
// score is in critical territory. Pure SVG + CSS, no chart library, so it
// stays in our own dark/red theme.
function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

const TICK_COUNT = 64;
const TICK_INNER = 5;
const TICK_OUTER = 5;

export default function RiskGauge({
  score,
  max = 100,
  color,
  trackColor = "#17171a",
  size = 176,
  label,
  sublabel,
  critical = false,
}: {
  score: number;
  max?: number;
  color: string;
  trackColor?: string;
  size?: number;
  label?: string;
  sublabel?: string;
  critical?: boolean;
}) {
  const pct = Math.max(0, Math.min(1, score / max));
  const filledTicks = Math.round(pct * TICK_COUNT);
  const animatedScore = useCountUp(score);
  // Every dimension below is tuned against the 176px default -- scale them
  // together so the gauge still reads correctly (ticks, inset, text) when
  // reused small (e.g. a compact per-row/per-card indicator) instead of
  // only ever looking right at one fixed size.
  const scale = size / 176;
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 14 * scale;
  const tickStroke = Math.max(1, 2.25 * scale);
  const scoreFontPx = Math.max(11, Math.round(size * 0.2));
  const labelFontPx = Math.max(7, Math.round(size * 0.0625));

  const ticks = Array.from({ length: TICK_COUNT }, (_, i) => {
    const angle = (i / TICK_COUNT) * 360;
    const p1 = polarToCartesian(cx, cy, r - TICK_INNER * scale, angle);
    const p2 = polarToCartesian(cx, cy, r + TICK_OUTER * scale, angle);
    return { i, p1, p2, filled: i < filledTicks };
  });

  return (
    <div
      className="relative shrink-0"
      style={{
        width: size,
        height: size,
        animation: critical ? "riskGaugePulse 2.4s ease-in-out infinite" : undefined,
        // @ts-expect-error -- CSS custom property, not a real React style key
        "--glow": color,
      }}
      role="img"
      aria-label={`${label ?? "Score"}: ${Math.round(score)} of ${max}`}
    >
      <style>{`
        @keyframes riskGaugeTickIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes riskGaugePulse {
          0%, 100% { filter: drop-shadow(0 0 6px var(--glow, transparent)); }
          50% { filter: drop-shadow(0 0 18px var(--glow, transparent)); }
        }
        @keyframes riskGaugeScoreIn {
          from { opacity: 0; transform: scale(0.85); }
          to { opacity: 1; transform: scale(1); }
        }
      `}</style>
      <svg
        width={size}
        height={size}
        className="block"
        style={{ filter: `drop-shadow(0 0 7px ${color}66)` }}
      >
        {ticks.map((t) => (
          <line
            key={t.i}
            x1={t.p1.x}
            y1={t.p1.y}
            x2={t.p2.x}
            y2={t.p2.y}
            stroke={t.filled ? color : trackColor}
            strokeWidth={tickStroke}
            strokeLinecap="round"
            style={
              t.filled
                ? {
                    opacity: 0,
                    animation: "riskGaugeTickIn 0.18s ease-out forwards",
                    animationDelay: `${t.i * 9}ms`,
                  }
                : undefined
            }
          />
        ))}
      </svg>
      <div
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{ animation: "riskGaugeScoreIn 0.5s ease-out 0.3s both" }}
      >
        <span
          className="font-bold tabular-nums"
          style={{ color, fontSize: scoreFontPx, lineHeight: 1 }}
        >
          {Math.round(animatedScore)}
        </span>
        {label ? (
          <span
            className="mt-1 uppercase tracking-[0.2em] text-zinc-500"
            style={{ fontSize: labelFontPx }}
          >
            {label}
          </span>
        ) : null}
        {sublabel ? (
          <span className="mt-0.5 text-zinc-600" style={{ fontSize: labelFontPx }}>
            {sublabel}
          </span>
        ) : null}
      </div>
    </div>
  );
}
