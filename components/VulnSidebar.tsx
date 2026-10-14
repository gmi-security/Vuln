"use client";

import { useEffect, useId, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import localFont from "next/font/local";
import { Menu, PanelLeftClose, PanelLeftOpen, X } from "lucide-react";
import { isNavigationActive, navigationHref, siteNavigation, type VulnNavItem } from "@/lib/navigation";
import type { Connector } from "@/lib/types";
import { useVulnNavigation } from "./VulnNavigationProvider";

const vibrocentric = localFont({ src: "../fonts/Vibrocentric Rg.otf", display: "swap" });

function StatusDot({ status }: { status: Connector["status"] }) {
  const color = status === "Connected" ? "bg-emerald-400" : status === "Demo Mode" ? "bg-amber-400" : "bg-zinc-600";
  return <span className={`h-1.5 w-1.5 rounded-full ${color}`} />;
}

export default function VulnSidebar({ companyId }: { companyId: string }) {
  const pathname = usePathname();
  const { collapsed, setCollapsed, capabilities, failed, retry } = useVulnNavigation();
  const { primary, tools } = siteNavigation(capabilities);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [syncAll, setSyncAll] = useState<{ running: boolean } | null>(null);
  const menuId = useId(), toggleRef = useRef<HTMLButtonElement>(null);
  useEffect(() => { setMobileOpen(false); }, [pathname]);
  useEffect(() => {
    if (!mobileOpen) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setMobileOpen(false); toggleRef.current?.focus(); }
    };
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [mobileOpen]);
  useEffect(() => {
    let alive = true;
    // Existing lightweight configuration/job status reads; no provider calls.
    const pollConnectors = () => fetch("/api/connectors", { cache: "no-store" })
      .then(r => r.ok ? r.json() : null).then(d => { if (alive && d) setConnectors(d.connectors ?? []); }).catch(() => {});
    const pollSyncAll = () => fetch("/api/connectors/sync-all", { cache: "no-store" })
      .then(r => r.ok ? r.json() : null).then(d => { if (alive && d) setSyncAll(d.status ?? null); }).catch(() => {});
    void pollConnectors(); void pollSyncAll();
    const connectorsId = setInterval(pollConnectors, 20_000), syncAllId = setInterval(pollSyncAll, 5_000);
    return () => { alive = false; clearInterval(connectorsId); clearInterval(syncAllId); };
  }, []);

  function links(items: VulnNavItem[]) {
    return items.map(item => {
      const Icon = item.icon, active = isNavigationActive(pathname, item.href);
      return <Link key={item.href} href={navigationHref(item.href, companyId)}
        aria-label={item.label} aria-current={active ? "page" : undefined} title={collapsed ? item.label : undefined}
        onClick={() => setMobileOpen(false)}
        className={`group flex items-center gap-3 rounded-2xl px-4 py-3 text-left transition ${collapsed ? "xl:justify-center xl:px-3" : ""} ${active ? "border border-[rgba(179,14,20,0.28)] bg-[linear-gradient(90deg,rgba(179,14,20,0.16),rgba(179,14,20,0.06))] text-white" : "text-zinc-300 hover:bg-zinc-900/70 hover:text-white"}`}>
        <Icon aria-hidden="true" size={18} className={`shrink-0 ${active ? "text-[#b30e14]" : "text-zinc-400 group-hover:text-zinc-200"}`} />
        <span className={`text-[15px] ${collapsed ? "xl:sr-only" : ""}`}>{item.label}</span>
      </Link>;
    });
  }

  return <aside className={`shrink-0 border-b border-[rgba(179,14,20,0.14)] bg-[#050505] xl:flex xl:min-h-screen xl:flex-col xl:border-b-0 xl:border-r ${collapsed ? "xl:w-[88px]" : "xl:w-[250px]"}`}>
    <div className="flex items-center justify-between px-4 py-4 xl:hidden">
      <Link href="/dashboard" className="text-lg font-semibold tracking-widest text-[#b30e14]" onClick={() => setMobileOpen(false)}>GMI VULN</Link>
      <button ref={toggleRef} type="button" aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
        aria-expanded={mobileOpen} aria-controls={menuId} onClick={() => setMobileOpen(open => !open)}
        className="rounded-xl border border-zinc-700 p-2 text-zinc-200">
        {mobileOpen ? <X size={20} /> : <Menu size={20} />}
      </button>
    </div>
    <div className={`hidden border-b border-[rgba(179,14,20,0.12)] py-8 xl:block ${collapsed ? "px-4" : "px-6"}`}>
      <div className={`flex gap-3 ${collapsed ? "justify-center" : "items-start justify-between"}`}>
        {!collapsed && <Link href="/dashboard" className="min-w-0" aria-label="GMI VULN dashboard">
          <div className={`${vibrocentric.className} text-[38px] leading-none tracking-[0.14em] text-[#b30e14]`}>VULN</div>
          <div className="mt-2 text-[12px] uppercase tracking-[0.34em] text-zinc-400">GMI Vulnerability Console</div>
        </Link>}
        <button type="button" onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="rounded-xl border border-zinc-800 bg-[#090909] p-2 text-zinc-400 transition hover:bg-zinc-900 hover:text-white">
          {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
        </button>
      </div>
    </div>
    <div id={menuId} className={`${mobileOpen ? "block" : "hidden"} pb-4 xl:block xl:pt-6`}>
      <nav aria-label="Main navigation" className={`space-y-2 px-4 ${collapsed ? "xl:px-3" : ""}`}>{links(primary)}</nav>
      {failed && <div className="px-4 py-3 text-xs text-zinc-300" role="status">Navigation options unavailable. <button onClick={retry} className="underline">Retry navigation</button></div>}
      {tools.length > 0 && <details key={pathname} open={tools.some(item => isNavigationActive(pathname, item.href))} className="mx-3 mt-4 border-t border-zinc-800 pt-3 text-zinc-300">
        <summary className="cursor-pointer px-2 py-2 text-xs">More tools</summary>
        <nav aria-label="Operational tools" className="mt-2 space-y-1">{links(tools)}</nav>
      </details>}
    </div>
    {!collapsed && connectors.length > 0 && <div className="mt-auto hidden px-6 pb-8 pt-6 xl:block">
      <div className="rounded-2xl border border-[rgba(179,14,20,0.14)] bg-[#080808] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-[11px] uppercase tracking-[0.24em] text-zinc-400">Scan Engines</div>
          {syncAll?.running && <Link href={navigationHref("/connectors", companyId)} className="text-xs text-[#ff8a8a]">Syncing…</Link>}
        </div>
        <div className="mt-3 space-y-2 text-[13px] text-zinc-300">{connectors.map(c => <div key={c.id} className="flex items-center gap-2"><StatusDot status={c.status} /><span>{c.name}{c.status === "Planned" ? " (planned)" : ""}</span></div>)}</div>
      </div>
    </div>}
  </aside>;
}
