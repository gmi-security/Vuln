import type { Finding } from "@/lib/types";

// SSVC — Stakeholder-Specific Vulnerability Categorization (CISA's decision
// framework). Instead of a raw score, it yields a decision: Act / Attend /
// Track* / Track, from exploitation status, exposure, automatability, and
// technical + mission impact. This is how modern gov programs prioritize —
// and it's what makes the queue defensible, not just "high CVSS".

export type SsvcDecision = "Act" | "Attend" | "Track*" | "Track";

export type SsvcResult = {
  decision: SsvcDecision;
  exploitation: "Active" | "PoC" | "None";
  automatable: boolean;
  technicalImpact: "Total" | "Partial";
  exposure: "Open" | "Controlled" | "Small";
  slaDays: number;
  reasons: string[];
};

const cvssOf = (f: Finding): number => f.cvssV3 || f.cvssV2 || f.cvss || 0;

const SLA_BY_DECISION: Record<SsvcDecision, number> = {
  Act: 15,
  Attend: 30,
  "Track*": 90,
  Track: 180,
};

export function ssvc(f: Finding): SsvcResult {
  const exploitation: SsvcResult["exploitation"] = f.kev
    ? "Active"
    : f.exploitAvailable || f.epss >= 0.1
      ? "PoC"
      : "None";
  const exposure: SsvcResult["exposure"] =
    f.assetExposure === "Internet-facing"
      ? "Open"
      : f.assetExposure === "Internal"
        ? "Controlled"
        : "Small";
  const automatable = f.assetExposure === "Internet-facing";
  const technicalImpact: SsvcResult["technicalImpact"] =
    cvssOf(f) >= 9 ? "Total" : "Partial";
  const highValue =
    f.assetCriticality === "Crown Jewel" || f.assetCriticality === "High";

  let decision: SsvcDecision;
  if (exploitation === "Active") {
    decision = exposure === "Open" || highValue ? "Act" : "Attend";
  } else if (exploitation === "PoC") {
    if (exposure === "Open" && (highValue || technicalImpact === "Total")) decision = "Act";
    else if (exposure === "Open" || highValue) decision = "Attend";
    else decision = "Track*";
  } else {
    if (exposure === "Open" && highValue && technicalImpact === "Total") decision = "Attend";
    else if (exposure === "Open" && (highValue || technicalImpact === "Total")) decision = "Track*";
    else decision = "Track";
  }

  // CISA KEV carries a hard 14-day remediation clock (BOD 22-01 style),
  // overriding the softer SSVC SLA.
  const slaDays = f.kev ? 14 : SLA_BY_DECISION[decision];

  const reasons: string[] = [];
  if (f.ransomware) reasons.push("CISA KEV — used in ransomware campaigns");
  else if (f.kev) reasons.push("On CISA KEV — actively exploited");
  else if (f.exploitAvailable) reasons.push("Public exploit available");
  if (f.epss >= 0.3) reasons.push(`EPSS ${Math.round(f.epss * 100)}% — likely exploitation`);
  if (f.assetExposure === "Internet-facing") reasons.push("Internet-facing asset");
  if (highValue) reasons.push(`${f.assetCriticality} asset`);
  if (technicalImpact === "Total") reasons.push(`CVSS ${cvssOf(f).toFixed(1)} — total impact`);

  return { decision, exploitation, automatable, technicalImpact, exposure, slaDays, reasons };
}

export function dueInfo(
  f: Finding,
  slaDays: number,
  now: number,
): { dueDate: string; overdue: boolean; daysLeft: number } {
  const due = new Date(f.firstSeen).getTime() + slaDays * 86_400_000;
  const daysLeft = Math.round((due - now) / 86_400_000);
  const open = f.status === "Open" || f.status === "In Remediation";
  return { dueDate: new Date(due).toISOString(), overdue: open && now > due, daysLeft };
}
