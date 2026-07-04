"use client";

import React from "react";

export function StatCard({
  label,
  value,
  sublabel,
  icon,
}: {
  label: string;
  value: React.ReactNode;
  sublabel: React.ReactNode;
  icon: React.ReactNode;
}) {
  return (
    <section className="rounded-[26px] border border-[rgba(179,14,20,0.14)] bg-[linear-gradient(180deg,#0b0b0b,#070707)] p-5 shadow-[0_20px_60px_rgba(0,0,0,0.26)]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-sm text-zinc-400">{label}</div>
          <div className="mt-3 text-5xl font-semibold tracking-[-0.04em] text-white">
            {value}
          </div>
          <div className="mt-3 text-sm text-zinc-500">{sublabel}</div>
        </div>
        <div className="flex h-14 w-14 items-center justify-center rounded-full border border-[rgba(179,14,20,0.22)] bg-[rgba(179,14,20,0.08)] text-[#b30e14]">
          {icon}
        </div>
      </div>
    </section>
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
        "rounded-[30px] border border-[rgba(179,14,20,0.16)] bg-[#050505] p-5 shadow-[0_20px_80px_rgba(0,0,0,0.34)]",
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
  "h-[52px] w-full rounded-2xl border border-zinc-800 bg-[#0b0b0b] px-4 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-[rgba(179,14,20,0.34)]";

export const selectClass =
  "h-[52px] rounded-2xl border border-zinc-800 bg-[#0b0b0b] px-4 text-sm text-white outline-none focus:border-[rgba(179,14,20,0.34)]";

export const primaryButtonClass =
  "flex h-[52px] items-center justify-center gap-2 rounded-2xl border border-[rgba(179,14,20,0.45)] bg-[rgba(179,14,20,0.16)] px-5 text-sm font-medium text-white transition hover:bg-[rgba(179,14,20,0.28)]";

export const ghostButtonClass =
  "flex h-[52px] items-center justify-center gap-2 rounded-2xl border border-zinc-800 bg-[#0b0b0b] px-5 text-sm text-white transition hover:bg-[#101010]";

export const scrollAreaClass =
  "overflow-y-auto [scrollbar-width:thin] [scrollbar-color:rgba(179,14,20,0.45)_#090909] [&::-webkit-scrollbar]:w-2 [&::-webkit-scrollbar-track]:bg-[#090909] [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[rgba(179,14,20,0.45)]";
