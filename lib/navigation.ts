import type * as React from "react";
import {
  Bug,
  Gauge,
  LayoutDashboard,
  PlugZap,
  Radar,
} from "lucide-react";

export type VulnNavItem = {
  label: string;
  icon: React.ElementType;
  href: string;
};

export const baseNavItems: VulnNavItem[] = [
  { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  { label: "Scans", icon: Radar, href: "/scans" },
  { label: "Findings", icon: Bug, href: "/findings" },
  { label: "Quantify", icon: Gauge, href: "/quantify" },
  { label: "Connectors", icon: PlugZap, href: "/connectors" },
];
