"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import localFont from "next/font/local";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { baseNavItems } from "@/lib/navigation";

const vibrocentric = localFont({
  src: "../fonts/Vibrocentric Rg.otf",
  display: "swap",
});

function isActivePath(pathname: string, href: string) {
  return pathname === href || pathname.startsWith(`${href}/`);
}

export default function VulnSidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const pathname = usePathname();

  return (
    <aside
      className={[
        "hidden shrink-0 xl:flex xl:flex-col xl:border-r xl:border-[rgba(179,14,20,0.14)] xl:bg-[#050505]",
        "transition-all duration-300 ease-in-out",
        collapsed ? "xl:w-[88px]" : "xl:w-[250px]",
      ].join(" ")}
    >
      <div
        className={[
          "border-b border-[rgba(179,14,20,0.12)] py-8",
          collapsed ? "px-4" : "px-6",
        ].join(" ")}
      >
        <div
          className={
            collapsed
              ? "flex justify-center"
              : "flex items-start justify-between gap-3"
          }
        >
          {!collapsed ? (
            <div className="min-w-0">
              <div
                className={`${vibrocentric.className} text-[38px] leading-none tracking-[0.14em] text-[#b30e14]`}
              >
                VULN
              </div>
              <div className="mt-2 text-[12px] uppercase tracking-[0.34em] text-zinc-400">
                GMI Vulnerability Console
              </div>
            </div>
          ) : null}

          <button
            type="button"
            onClick={onToggle}
            className="rounded-xl border border-zinc-800 bg-[#090909] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? (
              <PanelLeftOpen size={16} />
            ) : (
              <PanelLeftClose size={16} />
            )}
          </button>
        </div>
      </div>

      {!collapsed ? (
        <div className="px-6 pb-4 pt-6 text-xs uppercase tracking-[0.28em] text-zinc-500">
          Navigation
        </div>
      ) : (
        <div className="h-6" />
      )}

      <nav className={collapsed ? "space-y-2 px-3" : "space-y-2 px-4"}>
        {baseNavItems.map((item) => {
          const Icon = item.icon;
          const active = isActivePath(pathname, item.href);

          return (
            <Link
              key={item.label}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={[
                "group flex items-center rounded-2xl text-left transition",
                collapsed
                  ? "justify-center px-3 py-3"
                  : "w-full gap-3 px-4 py-3",
                active
                  ? "border border-[rgba(179,14,20,0.28)] bg-[linear-gradient(90deg,rgba(179,14,20,0.16),rgba(179,14,20,0.06))] text-white shadow-[inset_0_0_32px_rgba(179,14,20,0.10)]"
                  : "text-zinc-300 hover:bg-zinc-900/70 hover:text-white",
              ].join(" ")}
            >
              <Icon
                className={
                  active
                    ? "text-[#b30e14]"
                    : "text-zinc-400 group-hover:text-zinc-200"
                }
                size={18}
              />
              {!collapsed ? (
                <span className="text-[15px]">{item.label}</span>
              ) : null}
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto px-6 pb-8">
        {!collapsed ? (
          <div className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#080808] p-4">
            <div className="text-[11px] uppercase tracking-[0.24em] text-zinc-500">
              Scan Engines
            </div>
            <div className="mt-3 space-y-2 text-[13px] text-zinc-300">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                Nessus
              </div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                Vulners
              </div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                CrowdStrike
              </div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                SpiderFoot
              </div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                Artemis
              </div>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-zinc-600" />
                Qualys (planned)
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
