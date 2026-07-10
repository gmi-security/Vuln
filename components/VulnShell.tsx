"use client";

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import Image from "next/image";
import { signOut, useSession } from "next-auth/react";
import { ChevronDown, LogOut, PlugZap, Settings, UserCircle2 } from "lucide-react";
import VulnSidebar from "@/components/VulnSidebar";

// Page chrome shared by every screen: SONAR-style sidebar + header over a
// black radial-red console backdrop.
export default function VulnShell({
  eyebrow,
  title,
  subtitle,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { data: session } = useSession();
  const user = session?.user as
    | { name?: string | null; email?: string | null; login?: string; avatar?: string; role?: string }
    | undefined;
  const displayName = user?.name || user?.login || "Analyst";
  const displayRole = user?.role === "ADMIN" ? "Org Admin" : "Member";

  useEffect(() => {
    function onClick(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  return (
    <div className="flex min-h-screen bg-[radial-gradient(circle_at_18%_22%,rgba(179,14,20,0.08),transparent_26%),linear-gradient(180deg,#000_0%,#020202_100%)] text-white">
      <VulnSidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed((prev) => !prev)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="border-b border-[rgba(179,14,20,0.12)] bg-black px-6 py-6 lg:px-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <div className="text-[13px] uppercase tracking-[0.35em] text-[#b30e14]">
                {eyebrow}
              </div>
              <h1 className="mt-2 text-4xl font-semibold text-white">{title}</h1>
              <p className="mt-2 max-w-3xl text-zinc-400">{subtitle}</p>
            </div>

            <div className="flex items-center gap-3">
              {actions}
              <div ref={menuRef} className="relative">
                <button
                  onClick={() => setMenuOpen((prev) => !prev)}
                  className="flex items-center gap-3 rounded-2xl border border-zinc-800 bg-zinc-950 px-4 py-2.5 transition hover:bg-zinc-900"
                >
                  {user?.avatar ? (
                    <Image
                      src={user.avatar}
                      alt=""
                      width={24}
                      height={24}
                      className="rounded-full"
                      unoptimized
                    />
                  ) : (
                    <UserCircle2 className="text-zinc-300" size={20} />
                  )}
                  <span className="text-left">
                    <span className="block max-w-[150px] truncate text-sm font-medium text-white">
                      {displayName}
                    </span>
                    <span className="block text-xs uppercase tracking-[0.2em] text-zinc-500">
                      {displayRole}
                    </span>
                  </span>
                  <ChevronDown className="text-zinc-500" size={16} />
                </button>

                <div
                  className={[
                    "absolute right-0 z-20 mt-2 w-64 overflow-hidden rounded-2xl border border-zinc-800 bg-[#0a0a0a] shadow-[0_20px_60px_rgba(0,0,0,0.5)] transition",
                    menuOpen
                      ? "visible opacity-100"
                      : "invisible opacity-0",
                  ].join(" ")}
                >
                  <div className="border-b border-[rgba(179,14,20,0.12)] px-4 py-3">
                    <div className="truncate text-sm font-medium text-white">
                      {displayName}
                    </div>
                    <div className="mt-1 truncate text-xs text-zinc-500">
                      {user?.email || user?.login || "GMI Vulnerability Console"}
                    </div>
                  </div>
                  <div className="p-2">
                    <Link
                      href="/settings"
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-3 rounded-xl px-3 py-3 text-sm text-zinc-200 transition hover:bg-zinc-900"
                    >
                      <Settings size={16} className="text-zinc-400" />
                      Settings
                    </Link>
                    <Link
                      href="/connectors"
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-3 rounded-xl px-3 py-3 text-sm text-zinc-200 transition hover:bg-zinc-900"
                    >
                      <PlugZap size={16} className="text-zinc-400" />
                      Connectors
                    </Link>
                    <button
                      onClick={() => signOut({ callbackUrl: "/login" })}
                      className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-sm text-zinc-200 transition hover:bg-zinc-900"
                    >
                      <LogOut size={16} className="text-zinc-400" />
                      Sign out
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 space-y-6 px-6 py-8 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
