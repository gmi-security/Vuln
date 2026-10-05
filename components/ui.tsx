"use client";

import React from "react";
import { useCountUp } from "@/lib/useCountUp";

// Compact stat chip modeled on Kenna Security's top-row tiles (icon badge,
// a pill-shaped colored number, a small label underneath) -- meant to sit
// in a row next to a RiskGauge the way Kenna's "Top Priority / Active
// Breaches / Easily Exploitable" row sits beside its risk-score ring. Used
// on every page's stat row now; it replaced the plainer StatCard this
// session, which has no callers left.
export function KennaStatChip({
  icon,
  label,
  value,
  tone = "neutral",
  pulse = false,
}: {
  icon: React.ReactNode;
  label: React.ReactNode;
  value: number | null;
  tone?: "critical" | "warning" | "ok" | "neutral";
  // Ambient glow pulse for a tile that genuinely demands attention (e.g. a
  // nonzero actively-exploited count) -- used sparingly, not on every tile,
  // or it stops meaning anything.
  pulse?: boolean;
}) {
  const toneColor =
    tone === "critical" ? "#b30e14" : tone === "warning" ? "#f5a623" : tone === "ok" ? "#10b981" : "#9ca3af";
  const animated = useCountUp(value ?? 0);
  return (
    <div
      className="group relative flex flex-1 flex-col items-center gap-2 overflow-hidden rounded-2xl border px-3 py-4 text-center transition-all duration-300 hover:-translate-y-0.5"
      style={{
        borderColor: `${toneColor}2e`,
        background: `linear-gradient(165deg, ${toneColor}14, #090909 68%)`,
        animation: pulse ? "kennaChipPulse 2.4s ease-in-out infinite" : undefined,
        // @ts-expect-error -- CSS custom property, not a real React style key
        "--chip-glow": toneColor,
      }}
    >
      <style>{`
        @keyframes kennaChipPulse {
          0%, 100% { box-shadow: 0 0 0 1px var(--chip-glow, transparent) inset, 0 0 0 0 transparent; }
          50% { box-shadow: 0 0 0 1px var(--chip-glow, transparent) inset, 0 0 18px 1px color-mix(in srgb, var(--chip-glow, transparent) 45%, transparent); }
        }
      `}</style>
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{ boxShadow: `inset 0 0 28px ${toneColor}22, 0 8px 24px ${toneColor}26` }}
      />
      <span
        className="relative flex h-8 w-8 items-center justify-center rounded-full border"
        style={{ borderColor: `${toneColor}55`, color: toneColor, background: `${toneColor}1a` }}
      >
        {icon}
      </span>
      <span
        className="relative rounded-full px-3 py-0.5 text-lg font-bold tabular-nums"
        style={{ color: toneColor, background: `${toneColor}14` }}
      >
        {value === null ? "—" : Math.round(animated).toLocaleString()}
      </span>
      <span className="relative text-[11px] leading-tight text-zinc-400">{label}</span>
    </div>
  );
}

export function PanelCard({
  eyebrow,
  description,
  actions,
  children,
  className,
}: {
  eyebrow: string;
  description?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={[
        "rounded-3xl border border-[rgba(179,14,20,0.16)] bg-[#050505] p-5 shadow-[0_20px_60px_rgba(10,1,2,0.4)]",
        className ?? "",
      ].join(" ")}
    >
      <div className="mb-4 flex items-center justify-between gap-4">
        <div>
          <div className="text-[13px] uppercase tracking-[0.34em] text-[#b30e14]">
            {eyebrow}
          </div>
          {description ? (
            <p className="mt-2 text-zinc-500">{description}</p>
          ) : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Pill({
  className,
  children,
}: {
  className: string;
  children: React.ReactNode;
}) {
  return (
    <span
      className={`inline-flex rounded-full px-3 py-1 text-xs font-medium ${className}`}
    >
      {children}
    </span>
  );
}

export const inputClass =
  "h-11 w-full rounded-xl border border-zinc-800 bg-[#0b0b0b] px-4 text-sm text-white outline-none transition duration-200 placeholder:text-zinc-500 focus:border-[rgba(179,14,20,0.45)] focus:ring-2 focus:ring-[rgba(179,14,20,0.18)]";

export const selectClass =
  "h-11 rounded-xl border border-zinc-800 bg-[#0b0b0b] px-4 text-sm text-white outline-none transition duration-200 focus:border-[rgba(179,14,20,0.45)] focus:ring-2 focus:ring-[rgba(179,14,20,0.18)]";

export const primaryButtonClass =
  "flex h-11 items-center justify-center gap-2 rounded-xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] px-5 text-sm font-medium text-white transition duration-200 hover:bg-[rgba(179,14,20,0.28)] active:scale-[0.98] focus-visible:ring-2 focus-visible:ring-[rgba(179,14,20,0.4)] focus-visible:outline-none";

export const ghostButtonClass =
  "flex h-11 items-center justify-center gap-2 rounded-xl border border-zinc-800 bg-[#0b0b0b] px-5 text-sm text-white transition duration-200 hover:border-zinc-700 hover:bg-[#101010] active:scale-[0.98] focus-visible:ring-2 focus-visible:ring-[rgba(179,14,20,0.3)] focus-visible:outline-none";

export const scrollAreaClass =
  "overflow-y-auto [scrollbar-width:thin] [scrollbar-color:rgba(179,14,20,0.45)_#090909] [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-[#090909] [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[rgba(179,14,20,0.45)]";
