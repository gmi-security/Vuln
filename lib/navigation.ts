import type * as React from "react";
import {
  Bug,
  Building2,
  CalendarClock,
  ClipboardCheck,
  Database,
  Flame,
  GitBranch,
  LayoutDashboard,
  PlugZap,
  Radar,
  ScanSearch,
  Share2,
  ShieldCheck,
  SlidersHorizontal,
  Timer,
} from "lucide-react";

export type VulnNavItem = {
  label: string;
  icon: React.ElementType;
  href: string;
};

// Existing operational tools. Attack Surface and Quantify remain available
// through reporting rather than duplicate menu entries. The shared navigation
// adds the Dashboard home link and the feature-enabled customer views below.
export const baseNavItems: VulnNavItem[] = [
  { label: "Prioritize", icon: Flame, href: "/priorities" },
  { label: "Companies", icon: Building2, href: "/companies" },
  { label: "Scans", icon: Radar, href: "/scans" },
  { label: "Schedule", icon: CalendarClock, href: "/schedule" },
  { label: "Coverage", icon: ScanSearch, href: "/coverage" },
  { label: "Findings", icon: Bug, href: "/findings" },
  { label: "Attack Paths", icon: Share2, href: "/attack-paths" },
  { label: "Compliance", icon: ClipboardCheck, href: "/compliance" },
  { label: "Remediation SLA", icon: Timer, href: "/sla" },
  { label: "AppSec", icon: GitBranch, href: "/appsec" },
  { label: "Scanner Telemetry", icon: Database, href: "/scanner-telemetry" },
  { label: "Connectors", icon: PlugZap, href: "/connectors" },
];

// Old routes stay available as operational drilldowns during the UI rollout.
// Settings is appended by the sidebar, as in the existing navigation.
export const remediationNavItems: VulnNavItem[] = [
  { label: "Remediation", icon: Flame, href: "/remediation" },
  ...baseNavItems.filter(item => ["/companies", "/appsec", "/scanner-telemetry", "/connectors"].includes(item.href)),
];

export function siteNavigation(capabilities: { enabled: boolean; remediationEnabled: boolean } | null) {
  const primary = capabilities === null
    ? remediationNavItems
    : capabilities.remediationEnabled ? remediationNavItems : baseNavItems;
  return {
    primary: [
      { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
      ...primary,
      ...(capabilities?.enabled && !capabilities.remediationEnabled ? [{ label: "Reporting", icon: ShieldCheck, href: "/reporting" }] : []),
      { label: "Settings", icon: SlidersHorizontal, href: "/settings" },
    ],
    tools: capabilities?.remediationEnabled ? [
      { label: "Original reporting", icon: ShieldCheck, href: "/reporting" },
      ...baseNavItems.filter(item => !remediationNavItems.some(main => main.href === item.href)),
    ] : [],
  };
}

export function navigationHref(href: string, companyId: string) {
  if (companyId && ["/findings", "/scans", "/coverage", "/attack-paths", "/compliance"].includes(href))
    return `${href}?${new URLSearchParams({ company: companyId })}`;
  return companyId && ["/remediation", "/connectors", "/reporting", "/appsec"].includes(href)
    ? `${href}?${new URLSearchParams({ companyId })}` : href;
}

export function isNavigationActive(pathname: string, href: string) {
  return pathname === href || pathname.startsWith(`${href}/`);
}
