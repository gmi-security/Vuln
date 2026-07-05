import type * as React from "react";
import {
  Bug,
  Building2,
  ClipboardCheck,
  Flame,
  Gauge,
  Globe,
  LayoutDashboard,
  PlugZap,
  Radar,
  ScanSearch,
  Share2,
  Timer,
} from "lucide-react";

export type VulnNavItem = {
  label: string;
  icon: React.ElementType;
  href: string;
};

export const baseNavItems: VulnNavItem[] = [
  { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  { label: "Prioritize", icon: Flame, href: "/priorities" },
  { label: "Companies", icon: Building2, href: "/companies" },
  { label: "Scans", icon: Radar, href: "/scans" },
  { label: "Coverage", icon: ScanSearch, href: "/coverage" },
  { label: "Findings", icon: Bug, href: "/findings" },
  { label: "Attack Surface", icon: Globe, href: "/attack-surface" },
  { label: "Attack Paths", icon: Share2, href: "/attack-paths" },
  { label: "Compliance", icon: ClipboardCheck, href: "/compliance" },
  { label: "Remediation SLA", icon: Timer, href: "/sla" },
  { label: "Quantify", icon: Gauge, href: "/quantify" },
  { label: "Connectors", icon: PlugZap, href: "/connectors" },
];
