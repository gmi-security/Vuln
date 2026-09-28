import type { SlaSettings, SlaSeverity } from "./types";

const RANK: SlaSeverity[] = ["Critical", "High", "Medium", "Low"];

// A row's severity may arrive in CrowdStrike's uppercase convention
// (CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN) or this app's own title-case
// Severity (Critical/High/.../Info) depending on the source. Normalized
// case-insensitively and returned in the canonical title-case form the
// org's real SLA config (Settings > SLA) is keyed by.
export function worstSeverityOf(rows: { severity?: string | null }[]): SlaSeverity | null {
  const present = new Set(rows.map((r) => r.severity?.toUpperCase()).filter(Boolean));
  for (const severity of RANK) if (present.has(severity.toUpperCase())) return severity;
  return null;
}

// Days a remediation of this severity is allowed to stay open before it's
// breaching the org's actual, configurable SLA -- not a flat constant.
// Unknown/no severity (no CVE severity recorded, or a NONE/UNKNOWN grade)
// falls back to the High threshold, a middle ground that's neither too lax
// nor too aggressive.
export function slaDaysFor(worstSeverity: string | null | undefined, sla: SlaSettings): number {
  const key = worstSeverity && (RANK as string[]).includes(worstSeverity) ? (worstSeverity as SlaSeverity) : null;
  return sla[key ?? "High"];
}
