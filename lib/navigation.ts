import type * as React from "react";
import {
  Bug,
  Building2,
  CalendarClock,
  ClipboardCheck,
  Database,
  Flame,
  GitBranch,
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

// Dashboard, Attack Surface, and Quantify are intentionally not linked here
// -- their routes/components still exist (/dashboard, /attack-surface,
// /quantify), but their functionality is now superseded by the Reporting
// page (per-customer report, attack-surface exposures, and the
// Risk-Based Vulnerability Management Total-Open-Risk/Swath system
// respectively), so surfacing both was duplicate navigation, not duplicate
// capability worth keeping two entry points for.
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
