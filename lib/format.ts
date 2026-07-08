import type { ConnectorId, FindingStatus, ScanStatus, Severity } from "@/lib/types";

export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatAge(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const days = Math.floor(ms / 86_400_000);
  if (days > 0) return `${days}d`;
  const hours = Math.floor(ms / 3_600_000);
  if (hours > 0) return `${hours}h`;
  return `${Math.max(1, Math.floor(ms / 60_000))}m`;
}

export const connectorLabels: Record<ConnectorId, string> = {
  nessus: "Nessus",
  vulners: "Vulners",
  crowdstrike: "CrowdStrike",
  defender: "Defender",
  qualys: "Qualys",
  spiderfoot: "SpiderFoot",
  artemis: "Artemis",
  burp: "Burp Suite",
  nmap: "Nmap",
};

export const severityClass: Record<Severity, string> = {
  Critical: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
  High: "bg-[rgba(245,110,35,0.12)] text-orange-300 border border-orange-900/60",
  Medium: "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Low: "bg-[rgba(74,163,255,0.10)] text-sky-300 border border-sky-900/60",
  Info: "bg-zinc-900 text-zinc-400 border border-zinc-800",
};

export const scanStatusClass: Record<ScanStatus, string> = {
  Queued: "bg-zinc-900 text-zinc-300 border border-zinc-800",
  Running: "bg-[rgba(179,14,20,0.14)] text-[#ff4d57] border border-[rgba(179,14,20,0.40)]",
  Paused: "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Completed: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
  Stopped: "bg-zinc-900 text-zinc-400 border border-zinc-800",
  Failed: "bg-[rgba(179,14,20,0.20)] text-[#ff4d57] border border-[rgba(179,14,20,0.50)]",
};

export const findingStatusClass: Record<FindingStatus, string> = {
  Open: "bg-[rgba(179,14,20,0.14)] text-[#ff4d57] border border-[rgba(179,14,20,0.40)]",
  "In Remediation": "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  "Risk Accepted": "bg-[rgba(167,139,250,0.10)] text-violet-300 border border-violet-900/60",
  "False Positive": "bg-zinc-900 text-zinc-400 border border-zinc-800",
  Resolved: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
};

export const riskPriorityClass: Record<string, string> = {
  Critical: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
  High: "bg-[rgba(245,110,35,0.12)] text-orange-300 border border-orange-900/60",
  Medium: "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Low: "bg-[rgba(74,163,255,0.10)] text-sky-300 border border-sky-900/60",
  Info: "bg-zinc-900 text-zinc-400 border border-zinc-800",
};

export const exposureClass: Record<string, string> = {
  "Internet-facing": "text-[#ff4d57]",
  Internal: "text-zinc-300",
  Isolated: "text-sky-300",
};

export const compositeBandClass: Record<string, string> = {
  Critical: "bg-[rgba(179,14,20,0.16)] text-[#ff4d57] border border-[rgba(179,14,20,0.45)]",
  High: "bg-[rgba(245,110,35,0.12)] text-orange-300 border border-orange-900/60",
  Elevated: "bg-[rgba(245,166,35,0.10)] text-amber-300 border border-amber-900/60",
  Guarded: "bg-[rgba(74,163,255,0.10)] text-sky-300 border border-sky-900/60",
  Low: "bg-emerald-950/60 text-emerald-300 border border-emerald-900/60",
};

export function compositeColor(score: number): string {
  if (score >= 80) return "#b30e14";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#f5a623";
  if (score >= 20) return "#4aa3ff";
  return "#10b981";
}

export function riskColor(score: number): string {
  if (score >= 80) return "#b30e14";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#f5a623";
  if (score >= 20) return "#4aa3ff";
  return "#52525b";
}

export const severityBarColor: Record<Severity, string> = {
  Critical: "#b30e14",
  High: "#f97316",
  Medium: "#f5a623",
  Low: "#4aa3ff",
  Info: "#52525b",
};
