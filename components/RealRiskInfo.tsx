"use client";

import React, { useState } from "react";
import { Info } from "lucide-react";

// Explains the Real Risk composite score wherever it's labeled — an info
// icon + popover rather than a dedicated page, so the definition sits right
// next to the number it's explaining.
export default function RealRiskInfo() {
  const [open, setOpen] = useState(false);
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="How Real Risk is calculated"
        className="text-zinc-500 transition hover:text-zinc-300"
      >
        <Info size={13} />
      </button>
      {open ? (
        <div className="absolute left-0 top-6 z-30 w-80 rounded-2xl border border-zinc-800 bg-[#0a0a0a] p-4 text-xs normal-case leading-relaxed tracking-normal text-zinc-300 shadow-[0_20px_60px_rgba(0,0,0,0.5)]">
          <div className="mb-2 text-[11px] uppercase tracking-[0.24em] text-[#b30e14]">
            How Real Risk is calculated
          </div>
          <p className="mb-2">
            A 0–100 composite score, not raw CVSS. Three layers multiply
            together, so a finding only approaches 100 when all three are
            true at once:
          </p>
          <ul className="mb-2 list-disc space-y-1 pl-4">
            <li>
              <span className="text-zinc-100">Impact</span> — the CVSS base
              score, normalized.
            </li>
            <li>
              <span className="text-zinc-100">Threat</span> — is it a CISA
              KEV? Used in ransomware? Public exploit available? EPSS
              likelihood of exploitation.
            </li>
            <li>
              <span className="text-zinc-100">Environment</span> — the
              asset's real exposure (internet-facing vs. isolated) and
              business criticality.
            </li>
          </ul>
          <p>
            An active{" "}
            <span className="text-zinc-100">compensating control</span>{" "}
            (documented mitigation — e.g. a WAF blocking the exploit path)
            reduces the score by its stated effectiveness. The underlying
            CVE stays open; the risk it poses today is lower. Set these per
            customer on the company's page.
          </p>
        </div>
      ) : null}
    </span>
  );
}
