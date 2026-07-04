import type * as React from "react";
import {
  Bug,
  Building2,
  Gauge,
  LayoutDashboard,
  PlugZap,
  Radar,
  ScanSearch,
  Share2,
} from "lucide-react";

export type VulnNavItem = {
  label: string;
  icon: React.ElementType;
  href: string;
};

export const baseNavItems: VulnNavItem[] = [
  { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  { label: "Companies", icon: Building2, href: "/companies" },
  { label: "Scans", icon: Radar, href: "/scans" },
  { label: "Coverage", icon: ScanSearch, href: "/coverage" },
  { label: "Findings", icon: Bug, href: "/findings" },
  { label: "Attack Paths", icon: Share2, href: "/attack-paths" },
  { label: "Quantify", icon: Gauge, href: "/quantify" },
  { label: "Connectors", icon: PlugZap, href: "/connectors" },
];
