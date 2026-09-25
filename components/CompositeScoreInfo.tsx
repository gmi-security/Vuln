"use client";

import React, { useState } from "react";
import { Info } from "lucide-react";

// Explains the Composite risk score — a portfolio/company-level posture
// number, distinct from a single finding's Real Risk score (see
// RealRiskInfo). Same info-icon-plus-popover pattern.
export default function CompositeScoreInfo() {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="How Composite risk is calculated"
        className="text-zinc-500 transition hover:text-zinc-300"
      >
        <Info size={13} />
      </button>
      {open ? (
        <div className="absolute left-0 top-6 z-30 w-80 rounded-2xl border border-zinc-800 bg-[#0a0a0a] p-4 text-xs normal-case leading-relaxed tracking-normal text-zinc-300 shadow-[0_20px_60px_rgba(0,0,0,0.5)]">
          <div className="mb-2 text-[11px] uppercase tracking-[0.24em] text-[#b30e14]">
            How Composite risk is calculated
          </div>
          <p className="mb-2">
            A 0–100 portfolio-level posture score (higher = worse) — not the
            same thing as one finding's Real Risk score. Four weighted
            components:
          </p>
          <ul className="mb-2 list-disc space-y-1 pl-4">
            <li>
              <span className="text-zinc-100">Exposure (40%)</span> —
              severity × exploit-availability × EPSS load across all open
              findings.
            </li>
            <li>
              <span className="text-zinc-100">KEV pressure (25%)</span> — %
              of open findings that are a CISA Known Exploited
              Vulnerability.
            </li>
            <li>
              <span className="text-zinc-100">SLA breach (20%)</span> — % of
              open findings past their remediation SLA deadline.
            </li>
            <li>
              <span className="text-zinc-100">Coverage gap (15%)</span> — %
              of known inventory assets that haven't turned up in any scan
              yet. Dropped (and the rest reweighted) when there's no
              inventory to measure against.
            </li>
          </ul>
          <p>
            Bands: <span className="text-zinc-100">Low</span> 0–19 ·{" "}
            <span className="text-zinc-100">Guarded</span> 20–39 ·{" "}
            <span className="text-zinc-100">Elevated</span> 40–59 ·{" "}
            <span className="text-zinc-100">High</span> 60–79 ·{" "}
            <span className="text-zinc-100">Critical</span> 80–100.
          </p>
        </div>
      ) : null}
    </span>
  );
}
