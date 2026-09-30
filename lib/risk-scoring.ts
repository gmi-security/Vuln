// Risk-Based Vulnerability Management scoring engine. Pure functions, no I/O
// -- callers gather enrichment/asset context and pass it in. The score is
// deliberately NOT cvss*100: technical severity is one of five independent
// components, so a vulnerability under active exploitation can outscore a
// higher-CVSS one that nobody is exploiting (see the worked test cases in
// tests/risk-scoring.test.mjs).
//
// Weights are a config object, not magic numbers scattered through the
// formula, so they can later be overridden from risk_config without
// touching this file (see lib/risk-scoring-store.ts's risk_config table).

export type RiskWeights = {
  technicalMax: number;
  exploitLikelihoodMax: number;
  threatActivityMax: number;
  assetContextMax: number;
  additionalContextMax: number;
  threatActivity: { kev: number; activeExploitation: number; knownExploit: number; ransomware: number };
  assetContext: { internetExposed: number; identityInfrastructure: number; domainController: number; production: number; healthcareIomt: number; criticalBusinessApp: number; clientDesignatedCritical: number };
  additionalContext: { ageBrackets: { days: number; points: number }[]; noPatchAvailable: number; repeatedDetection: number; widespreadExposure: number };
};

// Defaults match the model in the RBVM spec: 250/250/200/200/100 = 1000 cap.
export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  technicalMax: 250,
  exploitLikelihoodMax: 250,
  threatActivityMax: 200,
  assetContextMax: 200,
  additionalContextMax: 100,
  threatActivity: { kev: 110, activeExploitation: 110, knownExploit: 55, ransomware: 60 },
  assetContext: { internetExposed: 60, identityInfrastructure: 70, domainController: 70, production: 40, healthcareIomt: 50, criticalBusinessApp: 45, clientDesignatedCritical: 60 },
  additionalContext: {
    ageBrackets: [{ days: 365, points: 25 }, { days: 180, points: 18 }, { days: 90, points: 10 }, { days: 30, points: 4 }],
    noPatchAvailable: -15, repeatedDetection: 15, widespreadExposure: 15,
  },
};

export type AssetType = "server" | "workstation" | "identity" | "domain_controller" | "network" | "iot" | "other";

export type RiskScoreInput = {
  cve: string;
  cvss: number | null;               // 0-10, null if unknown
  epssProbability: number | null;    // 0-1
  epssPercentile: number | null;     // 0-1
  cisaKev: boolean;
  knownExploit: boolean;             // public exploit/PoC/framework module exists
  activeExploitation: boolean;       // confirmed exploitation observed (distinct from KEV)
  ransomwareAssociation: boolean;
  publishedAt: string | null;        // ISO date the CVE was published/disclosed
  patchAvailable: boolean | null;    // null = unknown, treated as available (don't punish unknowns)
  repeatedDetection: boolean;        // same finding re-detected after a prior close/fix attempt
  widespreadExposure: boolean;       // this CVE affects many assets in the environment
  internetExposed: boolean;
  assetCriticality: "Crown Jewel" | "High" | "Normal" | "Low";
  assetType: AssetType;
  production: boolean;
  healthcareIomt: boolean;
  criticalBusinessApp: boolean;
  clientDesignatedCritical: boolean;
  now?: string; // injectable for deterministic tests; defaults to current time
};

export type RiskScoreBreakdown = {
  technical: number;
  exploitLikelihood: number;
  threatActivity: number;
  assetContext: number;
  additionalContext: number;
  total: number;
  reasons: string[];
};

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function technicalScore(input: RiskScoreInput, w: RiskWeights): { score: number; reason?: string } {
  if (input.cvss == null) return { score: w.technicalMax * 0.4 };
  const score = Math.round((clamp(input.cvss, 0, 10) / 10) * w.technicalMax);
  return { score, reason: `CVSS ${input.cvss.toFixed(1)}` };
}

function exploitLikelihoodScore(input: RiskScoreInput, w: RiskWeights): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  // EPSS probability is the primary driver; percentile nudges within that --
  // a 5% probability that's still 99th-percentile (rare model output) is
  // still worth flagging distinctly from a run-of-the-mill 5%.
  const prob = input.epssProbability ?? 0;
  const pct = input.epssPercentile ?? prob;
  const base = Math.round(clamp(prob, 0, 1) * (w.exploitLikelihoodMax * 0.85));
  const percentileBonus = Math.round(clamp(pct, 0, 1) * (w.exploitLikelihoodMax * 0.15));
  const score = clamp(base + percentileBonus, 0, w.exploitLikelihoodMax);
  if (input.epssProbability != null) reasons.push(`EPSS probability ${Math.round(input.epssProbability * 100)}%`);
  return { score, reasons };
}

function threatActivityScore(input: RiskScoreInput, w: RiskWeights): { score: number; reasons: string[] } {
  const t = w.threatActivity;
  let score = 0;
  const reasons: string[] = [];
  if (input.cisaKev) { score += t.kev; reasons.push("CISA Known Exploited Vulnerability"); }
  if (input.activeExploitation) { score += t.activeExploitation; reasons.push("Active exploitation reported"); }
  if (input.knownExploit) { score += t.knownExploit; reasons.push("Public exploit available"); }
  if (input.ransomwareAssociation) { score += t.ransomware; reasons.push("Ransomware-associated vulnerability"); }
  return { score: clamp(score, 0, w.threatActivityMax), reasons };
}

function assetContextScore(input: RiskScoreInput, w: RiskWeights): { score: number; reasons: string[] } {
  const a = w.assetContext;
  let score = 0;
  const reasons: string[] = [];
  if (input.internetExposed) { score += a.internetExposed; reasons.push("Internet-facing asset"); }
  if (input.assetType === "identity") { score += a.identityInfrastructure; reasons.push("Identity infrastructure"); }
  if (input.assetType === "domain_controller") { score += a.domainController; reasons.push("Domain controller"); }
  if (input.production) { score += a.production; reasons.push(input.assetType === "workstation" ? "Production workstation" : "Production server"); }
  if (input.healthcareIomt) { score += a.healthcareIomt; reasons.push("Healthcare / IoMT asset"); }
  if (input.criticalBusinessApp) { score += a.criticalBusinessApp; reasons.push("Critical business application"); }
  if (input.clientDesignatedCritical) { score += a.clientDesignatedCritical; reasons.push("Client-designated critical asset"); }
  // Crown Jewel/High criticality scales whatever else applied, rather than
  // adding its own flat bonus -- a criticality label alone (with no other
  // asset-context signal) shouldn't out-score a genuinely internet-facing DC.
  const criticalityMultiplier = { "Crown Jewel": 1.25, High: 1.1, Normal: 1, Low: 0.85 }[input.assetCriticality];
  score = Math.round(score * criticalityMultiplier);
  return { score: clamp(score, 0, w.assetContextMax), reasons };
}

function ageDays(publishedAt: string | null, now: string): number {
  if (!publishedAt) return 0;
  const days = (new Date(now).getTime() - new Date(publishedAt).getTime()) / 86_400_000;
  return Number.isFinite(days) ? Math.max(0, days) : 0;
}

function additionalContextScore(input: RiskScoreInput, w: RiskWeights): { score: number; reasons: string[] } {
  const a = w.additionalContext;
  let score = 0;
  const reasons: string[] = [];
  const now = input.now ?? new Date().toISOString();
  const days = ageDays(input.publishedAt, now);
  const bracket = a.ageBrackets.find((b) => days >= b.days);
  if (bracket) { score += bracket.points; reasons.push(`Known for ${Math.round(days)}+ days`); }
  if (input.patchAvailable === false) { score += a.noPatchAvailable; reasons.push("No patch available yet"); }
  if (input.repeatedDetection) { score += a.repeatedDetection; reasons.push("Repeated detection after prior remediation attempt"); }
  if (input.widespreadExposure) { score += a.widespreadExposure; reasons.push("Widespread across the environment"); }
  return { score: clamp(score, 0, w.additionalContextMax), reasons };
}

export function calculateRiskScore(input: RiskScoreInput, weights: RiskWeights = DEFAULT_RISK_WEIGHTS): RiskScoreBreakdown {
  const technical = technicalScore(input, weights);
  const exploit = exploitLikelihoodScore(input, weights);
  const threat = threatActivityScore(input, weights);
  const asset = assetContextScore(input, weights);
  const additional = additionalContextScore(input, weights);
  const total = clamp(
    technical.score + exploit.score + threat.score + asset.score + additional.score,
    0, 1000,
  );
  const reasons = [
    ...(technical.reason ? [technical.reason] : []),
    ...exploit.reasons, ...threat.reasons, ...asset.reasons, ...additional.reasons,
  ];
  return { technical: technical.score, exploitLikelihood: exploit.score, threatActivity: threat.score, assetContext: asset.score, additionalContext: additional.score, total, reasons };
}

export type SwathThresholds = { swath1: number; swath2: number; swath3: number };
export const DEFAULT_SWATH_THRESHOLDS: SwathThresholds = { swath1: 800, swath2: 600, swath3: 400 };

function swathForScore(score: number, t: SwathThresholds): 1 | 2 | 3 | 4 {
  if (score >= t.swath1) return 1;
  if (score >= t.swath2) return 2;
  if (score >= t.swath3) return 3;
  return 4;
}

export type SwathResult = { calculatedSwath: 1 | 2 | 3 | 4; effectiveSwath: 1 | 2 | 3 | 4; elevationReason: string | null };

// Emergency elevation: some combinations warrant Swath 1 regardless of the
// numeric score landing it lower -- a moderate-CVSS KEV on an exposed asset
// is a today problem even if EPSS/age math alone wouldn't clear 800.
export function calculateSwath(
  input: Pick<RiskScoreInput, "cisaKev" | "activeExploitation" | "ransomwareAssociation" | "internetExposed" | "assetType" | "production" | "clientDesignatedCritical">,
  score: number,
  thresholds: SwathThresholds = DEFAULT_SWATH_THRESHOLDS,
): SwathResult {
  const calculatedSwath = swathForScore(score, thresholds);
  const catastrophicIdentity = (input.assetType === "identity" || input.assetType === "domain_controller") && input.clientDesignatedCritical;
  let elevationReason: string | null = null;
  if (input.cisaKev && input.internetExposed) elevationReason = "CISA KEV on an Internet-facing asset";
  else if (input.activeExploitation && (input.production || input.clientDesignatedCritical)) elevationReason = "Active exploitation on a critical asset";
  else if (input.ransomwareAssociation && input.internetExposed && input.production) elevationReason = "Ransomware-associated vulnerability on an exposed production asset";
  else if (catastrophicIdentity) elevationReason = "Tier-0 identity infrastructure risk";
  const effectiveSwath: 1 | 2 | 3 | 4 = elevationReason ? 1 : calculatedSwath;
  return { calculatedSwath, effectiveSwath, elevationReason };
}
